/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <sys/poll.h>

#include "vr_dpdk.h"
#include "nl_util.h"
#include "vr_dpdk_n3k_vhost.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/timerfd.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_hexdump.h>
#include <rte_vhost.h>
#include <rte_vdpa.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <linux/virtio_net.h>
#include <linux/virtio_ring.h>

#include <string.h>

static void
destroy_device(__attribute__((unused)) int vid)
{
    return;
}

static int
new_device(__attribute__((unused)) int vid)
{
    return 0;
}

static const struct vhost_device_ops virtio_net_device_ops = {
    .new_device = new_device,
    .destroy_device = destroy_device
};

static int
register_and_start_vhost_driver(const char *vhost_socket_path,
                                struct vr_interface *vif,
                                uint32_t vif_vdpa_did)
{
    int ret = rte_vhost_driver_register(vhost_socket_path,
        vif->vif_vhostuser_mode == VHOSTUSER_SERVER ? RTE_VHOST_USER_CLIENT : 0);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): rte_vhost_driver_register failure.\n", __func__);
        return -1;
    }

    ret = rte_vhost_driver_callback_register(vhost_socket_path,
                                             &virtio_net_device_ops);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): failed to register vhost driver callbacks.\n", __func__);
        goto unregister_vhost;
    }

    if (rte_vhost_driver_attach_vdpa_device(vhost_socket_path, vif_vdpa_did) != 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Could not attach vDPA device with id: %d", __func__, vif_vdpa_did);
        goto unregister_vhost;
    }

    if (rte_vhost_driver_start(vhost_socket_path) < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): rte_vhost_driver_start(%s) failed\n", __func__, vhost_socket_path);
        goto unregister_vhost;
    }

    return 0;

unregister_vhost:
    rte_vhost_driver_unregister(vhost_socket_path);
    return -1;
}

static int
configure_vhost_socket_dir(void)
{
    /* qemu in server mode needs rw access */
    const mode_t SOCKET_DIR_MODE = (S_IRWXU | S_IRWXG | S_IRWXO);
    int fd = -1;

    if ((fd = open(vr_socket_dir, O_DIRECTORY)) > 0) {
        struct stat st;

        if (fstat(fd, &st) < 0) {
            RTE_LOG(ERR, VROUTER,
                "%s(): Can't stat a file descriptor: %s", __func__, strerror(errno));
            close(fd);
            return -1;
        }

        if ((st.st_mode & ALLPERMS) != SOCKET_DIR_MODE) {
            if (fchmod(fd, SOCKET_DIR_MODE) < 0) {
                RTE_LOG(ERR, VROUTER,
                    "%s(): Can't chmod a file descriptor: %s", __func__, strerror(errno));
                close(fd);
                return -1;
            }
        }
    } else if ((fd = open(vr_socket_dir, 0)) > 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): %s exists and is not a directory", __func__, vr_socket_dir);
        close(fd);
        return -1;
    } else if (mkdir(vr_socket_dir, SOCKET_DIR_MODE) < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Can't create %s: %s", __func__, vr_socket_dir, strerror(errno));
        return -1;
    }

    /* FD wont't be used, close it */
    if (fd > 0) {
        close(fd);
    }

    return 0;
}

static int
get_vhost_socket_path(struct vr_interface *vif, size_t pathlen, char (*path)[pathlen])
{
    if (path == NULL || vif == NULL) {
        RTE_LOG(ERR, VROUTER, "%s(): invalid args", __func__);
        return -1;
    }

    strncpy(*path, vr_socket_dir, sizeof(*path) - 1);
    strncat(*path,
            "/" VR_UVH_VIF_PFX,
            pathlen - strlen(*path) - 1);
    strncat(*path,
            (char*)vif->vif_name,
            pathlen - strlen(*path) - 1);

    return 0;
}

void
vr_dpdk_n3k_vhost_unregister(struct vr_interface *vif)
{
    char vhost_socket_path[VR_UNIX_PATH_MAX];
    memset(vhost_socket_path, 0, sizeof(vhost_socket_path));

    if (vif == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): invalid vif;\n", __func__);
        return;
    }

    RTE_LOG(INFO, VROUTER,
        "%s(): id - %u; name - %s;\n", __func__, vif->vif_idx, vif->vif_name);

    int ret = get_vhost_socket_path(vif, RTE_DIM(vhost_socket_path), &vhost_socket_path);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "%s(): failed to construct vhost_socket_path", __func__);
        return;
    }

    rte_vhost_driver_detach_vdpa_device(vhost_socket_path);
    rte_vhost_driver_unregister(vhost_socket_path);
}

int
vr_dpdk_n3k_vhost_register(struct vr_interface *vif, uint32_t vif_vdpa_did)
{
    char vhost_socket_path[VR_UNIX_PATH_MAX] = {};
    int ret = -EINVAL;
    if (vif == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): invalid vif;\n", __func__);
        return ret;
    }

    RTE_LOG(INFO, VROUTER,
        "%s(): id - %u; name - %s;\n", __func__, vif->vif_idx, vif->vif_name);

    ret = get_vhost_socket_path(vif, RTE_DIM(vhost_socket_path), &vhost_socket_path);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "%s(): failed to construct vhost_socket_path", __func__);
        return ret;
    }

    ret = register_and_start_vhost_driver(vhost_socket_path, vif, vif_vdpa_did);
    if (ret != 0) {
        return ret;
    }

    RTE_LOG(INFO, VROUTER, "%s(): vr_dpdk_n3k_vhost_register(vif: %d)\n",
        __func__, vif->vif_idx);

    return 0;
}

int vr_dpdk_n3k_vhost_init(void)
{
    int ret = configure_vhost_socket_dir();

    return ret;
}

void vr_dpdk_n3k_vhost_exit(void)
{
    return;
}
