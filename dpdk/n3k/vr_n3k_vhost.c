/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <sys/poll.h>

#include "vr_dpdk.h"
#include "vr_dpdk_usocket.h"
#include "vr_n3k_vhost.h"
#include "../vr_dpdk_virtio.h"
#include "../vr_uvhost_client.h"
#include "../vr_uvhost_msg.h"
#include "../vr_uvhost_util.h"
#include "../vr_dpdk_filestore.h"

#include <fcntl.h>
#include <linux/virtio_net.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/timerfd.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

#include <rte_errno.h>
#include <rte_hexdump.h>
#include <rte_vhost.h>
#include <rte_vdpa.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <linux/virtio_net.h>
#include <linux/virtio_ring.h>

#include <string.h>

typedef int (*vr_uvh_msg_handler_fn)(vr_uvh_client_t *vru_cl);


/*
 * Return the basename given a full path
 * Note: Dont use posix library function
 * as it could change the original string
 */
static char *basename(char *string)
{
    char *tmp = &string[strlen(string)-1];
    /* find basename */
    while (tmp > string && *(tmp-1) != '/')
        tmp--;
    if (tmp == string)
        return NULL;
    return tmp+8; /* remove the uvh_vif_ */
}

static vr_uvh_client_t *
vr_uvh_get_client_by_ifname(char *ifname)
{
    unsigned int i = 0;

    for (i = 0; i < VR_UVH_MAX_CLIENTS; ++i) {
        vr_uvh_client_t *vru_cl = vr_uvhost_get_client(i);

        if (!vru_cl) {
            continue;
        }

        if (strcmp(vru_cl->vruc_path, ifname) == 0) {
            return vru_cl;
        }
    }

    return NULL;
}

static vr_uvh_client_t *
vr_uvh_get_client_by_vid(int vid)
{
    char ifname[VR_UNIX_PATH_MAX];

    if (rte_vhost_get_ifname(vid, ifname, VR_UNIX_PATH_MAX) != 0) {
        vr_uvhost_log("rte_vhost_get_ifname(%d) failed\n", vid);
        return NULL;
    }

    return vr_uvh_get_client_by_ifname(ifname);
}

static enum rte_vhost_msg_result
vr_uvh_vhost_set_vring_enable(int vid, struct VhostUserMsg *msg)
{
    uint16_t qid = msg->state.index / 2;
    bool enable = msg->state.num;
    bool is_vhost_txq = msg->state.index & 1;
    vr_uvh_client_t *vru_cl = vr_uvh_get_client_by_vid(vid);

    if (!vru_cl){
        vr_uvhost_log("Posthandling VHOST_USER_SET_VRING_ENABLE failed; vid = %d\n",
            vid);
        vr_uvhost_log("Could not retrieve vrouter's vhost user client\n");
        return RTE_VHOST_MSG_RESULT_ERR;
    }

    //librte_vhost interface's tx queue is connected to vrouter interface's rx queue and vice versa
    if (is_vhost_txq) {
        vr_dpdk_virtio_rx_queue_enable_disable(vru_cl->vruc_idx,
                                               vru_cl->vruc_vif_gen, qid,
                                               enable);
    } else {
        vr_dpdk_virtio_tx_queue_enable_disable(vru_cl->vruc_idx,
                                               vru_cl->vruc_vif_gen, qid,
                                               enable);
    }

    vr_uvhost_log("Posthandling VHOST_USER_SET_VRING_ENABLE succeeded; vid = %d, path = %s\n",
        vid, vru_cl->vruc_path);
    return RTE_VHOST_MSG_RESULT_NOT_HANDLED;
}

static enum rte_vhost_msg_result
vr_uvh_vhost_pre_msg_handler(int vid, void *_msg)
{
    return RTE_VHOST_MSG_RESULT_NOT_HANDLED;
}

static enum rte_vhost_msg_result
vr_uvh_vhost_post_msg_handler(int vid, void *_msg)
{
    struct VhostUserMsg *msg = _msg;

    if ((int)msg->request == VHOST_USER_SET_VRING_ENABLE) {
        return vr_uvh_vhost_set_vring_enable(vid, msg);
    }

    return RTE_VHOST_MSG_RESULT_NOT_HANDLED;
}

struct rte_vhost_user_extern_ops vhost_msg_handlers = {
    .pre_msg_handle = vr_uvh_vhost_pre_msg_handler,
    .post_msg_handle = vr_uvh_vhost_post_msg_handler,
};

/*
 * DPDK Vhost destroy device callback
 */
static void
destroy_device(int vid)
{
    vr_uvh_client_t *vru_cl = vr_uvh_get_client_by_vid(vid);
    if (!vru_cl) {
        vr_uvhost_log("Could not get vhost user client with vid = %d\n", vid);
        return;
    }
    vr_uvhost_log("Destroying device: vid = %d; path = %s\n", vid, vru_cl->vruc_path);
    vru_cl->vruc_fd = -1;
}

/*
 * DPDK Vhost new device callback
 */
static int
new_device(int vid)
{
    vr_uvh_client_t *vru_cl = vr_uvh_get_client_by_vid(vid);
    if (!vru_cl) {
        vr_uvhost_log("Could not get vhost user client with vid = %d\n", vid);
        return -1;
    }

    vr_uvhost_log("New Vhost device vid = %d; path = %s\n", vid, vru_cl->vruc_path);

    /* Explicitly enable notifications\ for vDPA */

    rte_vhost_enable_guest_notification(vid, VIRTIO_RXQ, 1);
    rte_vhost_enable_guest_notification(vid, VIRTIO_TXQ, 1);

    return 0;
}

static const struct vhost_device_ops virtio_net_device_ops = {
    .new_device = new_device,
    .destroy_device = destroy_device
};

void
vr_n3k_vhost_vif_remove_handler(unsigned char *vif_name)
{
    char unix_socket_path[108];
    memset(unix_socket_path, 0, sizeof(unix_socket_path));
    strncpy(unix_socket_path, vr_socket_dir, sizeof(unix_socket_path) - 1);
    strncat(unix_socket_path,
	    "/" VR_UVH_VIF_PFX,
	    sizeof(unix_socket_path) - strlen(unix_socket_path) - 1);
    strncat(unix_socket_path,
	    (char*)vif_name,
	    sizeof(unix_socket_path) - strlen(unix_socket_path) - 1);
    rte_vhost_driver_detach_vdpa_device(unix_socket_path);
    rte_vhost_driver_unregister(unix_socket_path);
}

/*
 * vr_uvh_nl_vif_add_handler - handle a vif add
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_n3k_vhost_vif_add_handler(unsigned char *vif_name, uint32_t vif_idx,
			     uint32_t vif_gen, uint32_t vif_nrxqs,
			     uint32_t vif_ntxqs, uint32_t vif_vdpa_did)
{
    vr_uvh_client_t *vru_cl = NULL;
    char unix_socket_path[108];
    int ret = -1;

    vr_uvhost_log(
      "Adding vif %d vif_name %s\n", vif_idx, vif_name);

    mkdir(vr_socket_dir, VR_DEF_SOCKET_DIR_MODE);

    /* qemu in server mode needs rw access */
    chmod(vr_socket_dir, 0777);

    memset(unix_socket_path, 0, sizeof(unix_socket_path));
    strncpy(unix_socket_path, vr_socket_dir, sizeof(unix_socket_path) - 1);
    strncat(unix_socket_path,
            "/" VR_UVH_VIF_PFX,
            sizeof(unix_socket_path) - strlen(unix_socket_path) - 1);
    strncat(unix_socket_path,
	    (char*)vif_name,
            sizeof(unix_socket_path) - strlen(unix_socket_path) - 1);

    ret = rte_vhost_driver_register(unix_socket_path, RTE_VHOST_USER_CLIENT);
    if (ret != 0) {
        vr_uvhost_log("rte_vhost_driver_register failure.\n");
        goto unregister_vhost;
    }

    ret = rte_vhost_driver_callback_register(unix_socket_path,
                                             &virtio_net_device_ops);
    if (ret != 0) {
        vr_uvhost_log("failed to register vhost driver callbacks.\n");
        goto unregister_vhost;
    }

    vru_cl = vr_uvhost_new_client(-1, unix_socket_path, vif_idx);
    if (vru_cl == NULL) {
        vr_uvhost_log("    error creating vif %u socket %s new vhost client\n",
		      vif_idx,
                      unix_socket_path);
        goto unregister_vhost;
    }

    vru_cl->vruc_idx = vif_idx;
    vru_cl->vruc_nrxqs = vif_nrxqs;
    vru_cl->vruc_ntxqs = vif_ntxqs;
    vru_cl->vruc_vif_gen = vif_gen;
    /* FIXME: workaround for agent issue #1796091
     * Agent sends vhostuser mode as client eventhough
     * its hardcoded in the api-server as server and
     * the port configuration from neutron shows as server.
     * Hardcode it to server mode as we dont use client
     * mode in > 5.x, until agent code is fixed.
     */
    vru_cl->vruc_vhostuser_mode = VRNU_VIF_MODE_SERVER;
    vru_cl->vruc_timer_fd = -1;

    if (rte_vhost_driver_attach_vdpa_device(unix_socket_path, vif_vdpa_did) != 0) {
	vr_uvhost_log("Could not attach vDPA device with id: %d", vif_vdpa_did);
	goto del_uvhost_client;
    }

    if (rte_vhost_driver_start(unix_socket_path) < 0) {
        vr_uvhost_log("rte_vhost_driver_start(%s) failed\n", unix_socket_path);
        goto del_uvhost_client;
    }

    /* Send netlink interface up message to agent */
    vr_uvh_nl_send_intf_state(1, vru_cl->vruc_idx, basename(vru_cl->vruc_path));

    vr_uvhost_log("vr_dpdk_virtio_set_vif_client(%d)\n", vif_idx);

    return 0;

del_uvhost_client:
    vr_uvhost_del_client(vru_cl);

unregister_vhost:
    rte_vhost_driver_unregister(unix_socket_path);
    return -1;
}
