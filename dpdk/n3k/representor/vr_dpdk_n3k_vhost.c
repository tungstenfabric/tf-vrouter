/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_representor_impl.h"

#include <sys/poll.h>

#include <vr_dpdk.h>
#include <nl_util.h>

#include "../../vr_dpdk_virtio.h"

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
    /* agent attaches info in the vif about what role
    will orchestrator configure hypervisor to perform in regards to setup of
    vhost user socket so tell the DPDK's librte_vhost the opposite, otherwise
    both hypervisor and vRouter (via DPDK) will perform the same role and won't connect
    uint64_t vif_vhost_connection_type =
        vif->vif_vhostuser_mode == VHOSTUSER_SERVER ? RTE_VHOST_USER_CLIENT : 0;

    int ret = rte_vhost_driver_register(vhost_socket_path,
        RTE_VHOST_USER_CLIENT);

        However, the vif_vhostuser_mode is not always filled, i.e.
    it is default initialized, that is, to value 0 (== VHOSTUSER_CLIENT).
    As the vif_vhostuser_mode is unreliable, limit vhost socket mode to
    client only.
    */
    int ret = rte_vhost_driver_register(vhost_socket_path,
        RTE_VHOST_USER_CLIENT);
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
get_vhost_socket_path(const char *name, char *path, size_t pathlen)
{
    if (path == NULL) {
        RTE_LOG(ERR, VROUTER, "%s(): invalid args", __func__);
        return -1;
    }

    snprintf(path, pathlen, "%s/%s%s",
        vr_socket_dir, VR_UVH_VIF_PFX, name);

    return 0;
}

void
vr_dpdk_n3k_vhost_unregister(const char *name)
{
    int ret;
    char vhost_socket_path[VR_UNIX_PATH_MAX];
    memset(vhost_socket_path, 0, sizeof(vhost_socket_path));

    RTE_LOG(DEBUG, VROUTER,
        "%s(name - %s): called\n", __func__, name);

    ret = get_vhost_socket_path(name, vhost_socket_path, RTE_DIM(vhost_socket_path));
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "%s(name - %s): failed to construct vhost_socket_path\n",
            __func__, name);
        goto out;
    }

    RTE_LOG(INFO, VROUTER,
        "%s(name - %s): started: socket - %s\n", __func__, name, vhost_socket_path);

    ret = rte_vhost_driver_detach_vdpa_device(vhost_socket_path);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "%s(name - %s): rte_vhost_driver_detach_vdpa_device failed\n",
            __func__, name);
    }

    ret = rte_vhost_driver_unregister(vhost_socket_path);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "%s(name - %s): rte_vhost_driver_unregister failed\n",
            __func__, name);
        goto out;
    }

    ret = 0;
out:
    RTE_LOG(INFO, VROUTER, "%s(): %s\n", __func__, ret ? "failed" : "success");
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

    RTE_LOG(DEBUG, VROUTER,
        "%s(): id - %u; name - %s;\n", __func__, vif->vif_idx, vif->vif_name);

    ret = get_vhost_socket_path((char *)vif->vif_name, vhost_socket_path, RTE_DIM(vhost_socket_path));
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "%s(): failed to construct vhost_socket_path", __func__);
        return ret;
    }

    ret = register_and_start_vhost_driver(vhost_socket_path, vif, vif_vdpa_did);
    if (ret != 0) {
        return ret;
    }

    RTE_LOG(DEBUG, VROUTER, "%s(): succeeded; vif: %d\n",
        __func__, vif->vif_idx);

    return 0;
}

int vr_dpdk_n3k_vhost_init(void)
{
    return configure_vhost_socket_dir();
}

void vr_dpdk_n3k_vhost_exit(void)
{
    return;
}
