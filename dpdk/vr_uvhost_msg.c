/*
 * vr_uvhost_msg.c - handlers for messages received by the user space
 * vhost thread.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include <sys/poll.h>

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"
#include "vr_dpdk_usocket.h"
#include "vr_uvhost_client.h"
#include "vr_uvhost_msg.h"
#include "vr_uvhost_util.h"
#include "vr_dpdk_filestore.h"

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

#define uvhm_client_name(vru_cl) (vru_cl->vruc_path + strlen(vr_socket_dir) \
    + sizeof(VR_UVH_VIF_PFX) - 1)

/*
 *  NAREN
 *  vr_dpdk_store_persist_feature()
 *
 */
// naren
static int vr_uvhm_set_vring_enable(vr_uvh_client_t *vru_cl, uint16_t vring_idx, int enable);
static int vr_uvhm_enable_disable_features(const char *file_path);

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

/*
 * Function to send interface state to Agent
 * state 0 - down
 * state 1 - up
 * Called when the VM goes down or comes up
 */
static void
vr_uvh_nl_send_intf_state(int state, int intf_index, char *intf_name)
{
    int nl_fd;
    char buf[1024];
    struct nlmsghdr *nlh;
    struct ifinfomsg *ifinfo;
    struct nlattr *nla;
    int len, n;
    char *if_name_buf;
    struct sockaddr_nl sa;

    if (intf_name == NULL)
        return;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR;



    nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd < 0) {
        vr_uvhost_log("Error creating netlink socket\n");
        goto error;
    }
    bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa));
    nlh = (struct nlmsghdr *)buf;

    nlh->nlmsg_len = NLMSG_HDRLEN + sizeof(struct ifinfomsg);
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;
    nlh->nlmsg_pid = 0;
    ifinfo = (struct ifinfomsg *)(buf + NLMSG_HDRLEN);

    ifinfo->ifi_family = 0;
    ifinfo->ifi_type = 0;
    ifinfo->ifi_type = 0;
    /* Set index to -1 as agent needs only the interface name */
    ifinfo->ifi_index = -1;
    if (state)
        ifinfo->ifi_flags = IFF_MULTICAST|IFF_RUNNING|IFF_BROADCAST|IFF_UP;
    else
        ifinfo->ifi_flags = IFF_BROADCAST|IFF_UP;
    /* ifi_change needs to be set to 0xFFFFFFFF by default
     * as its a reserved field
     */
    ifinfo->ifi_change = 0xFFFFFFFF;

    nla = (struct nlattr *)(buf + NLMSG_HDRLEN + sizeof(struct ifinfomsg));

    len = NLA_HDRLEN + NLA_ALIGN(strlen(intf_name) + 1);

    nla->nla_len = len;
    nla->nla_type = IFLA_IFNAME;

    if_name_buf = (char *)nla + NLA_HDRLEN;
    strcpy(if_name_buf, intf_name);

    len += (NLMSG_HDRLEN + sizeof(struct ifinfomsg));

    nlh->nlmsg_len = len;

    n = sendto(nl_fd, buf, len, 0, (struct sockaddr *)&sa, sizeof(sa));
    if (n != len) {
        vr_uvhost_log("Error sending netlink interface message\n");
    }

    close(nl_fd);
error:
    return;
}

static int vr_uvhm_enable_disable_features(const char *file_path)
{
    uint64_t support_flags;
    
    
    rte_vhost_driver_get_features(file_path, &support_flags);
    vr_uvhost_log("    Original SUPPORT FEATURES: returns 0x%"PRIx64"\n",
                                            support_flags);

    /*
       support_flags = (1ULL << VIRTIO_NET_F_CTRL_VQ) |
       (1ULL << VIRTIO_NET_F_CSUM) |
       (1ULL << VIRTIO_NET_F_GUEST_CSUM) |
       (1ULL << VIRTIO_NET_F_MQ) |
       (1ULL << VHOST_USER_F_PROTOCOL_FEATURES) |
       (1ULL << VHOST_F_LOG_ALL);
    */

    if (dpdk_check_rx_mrgbuf_disable())
        rte_vhost_driver_disable_features(file_path,
                                          1ULL << VIRTIO_NET_F_MRG_RXBUF);
    if (!vr_perfs) {
        rte_vhost_driver_disable_features(file_path,
                1ULL << VIRTIO_NET_F_HOST_TSO4);
        rte_vhost_driver_disable_features(file_path,
                1ULL << VIRTIO_NET_F_HOST_TSO6);
        rte_vhost_driver_disable_features(file_path,
                1ULL << VIRTIO_NET_F_GUEST_TSO4);
        rte_vhost_driver_disable_features(file_path,
                1ULL << VIRTIO_NET_F_GUEST_TSO6);
    }

    rte_vhost_driver_get_features(file_path, &support_flags);
    vr_uvhost_log("    UPDATED SUPPORT FEATURES: returns 0x%"PRIx64"\n",
                                            support_flags);
    return 0;
}

/*
 * vr_uvh_nl_vif_del_handler - handle a message from the netlink thread
 * to delete a vif.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvh_nl_vif_del_handler(vrnu_vif_del_t *msg)
{
    unsigned int cidx = msg->vrnu_vif_idx;
    vr_uvh_client_t *vru_cl;

    vr_uvhost_log("Deleting vif %d virtual device\n", cidx);

    if (cidx >= VR_UVH_MAX_CLIENTS) {
        vr_uvhost_log("    error deleting vif %u: invalid vif index\n", cidx);
        return -1;
    }

    vr_dpdk_virtio_set_vif_client(cidx, NULL);

    vru_cl = vr_uvhost_get_client(cidx);
    if (vru_cl == NULL) {
        vr_uvhost_log("    error deleting vif %d: no client found\n",
                      cidx);
        return -1;
    }
    /* Unmmap guest memory. */
    // uvhm_client_munmap(vru_cl);
    vr_uvhost_del_client(vru_cl);

    return 0;
}


// naren
static int vr_uvh_new_device_cb(int vid)
{
    vr_uvh_client_t *vru_cl;
    char file_path[VR_UNIX_PATH_MAX];
    vr_uvhost_log("    vhost callback vid %d\n",
                            vid);
    // get the path from the vhost device
    if (rte_vhost_get_ifname(vid, file_path, sizeof(file_path) - 1) < 0) {
        // error in finding the device name
    }

    vr_uvhost_log("    vhost callback ifname %s\n",
                            file_path);

    vru_cl = vr_uvhost_update_client(vid, file_path, VR_CLIENT_READY);
    if (vru_cl == NULL) {
        // fatal error
    vr_uvhost_log("    error vid = %d, ifname %s\n",
                            vid, file_path);
        return -1;
    }

    /* Disable notifications in queue callback fn. */
    rte_vhost_enable_guest_notification(vid, 0, 0);
    rte_vhost_enable_guest_notification(vid, 1, 0);

    vr_uvhm_set_vring_enable(vru_cl, 0, 1);
    vr_uvhm_set_vring_enable(vru_cl, 1, 1);
    
    /* Send netlink interface up message to agent */
    vr_uvh_nl_send_intf_state(1, vru_cl->vruc_idx, basename(vru_cl->vruc_path));
    return 0;
}

void vr_uvh_destroy_connection_cb(int vid)
{

}

/*
 * Handle the VHOST_USER_SET_VRING_ENABLE vhost-user protocol message.
 */
static int
vr_uvhm_set_vring_enable(vr_uvh_client_t *vru_cl, uint16_t vring_idx, int enable)
{
    vq_ready_state_t vq_state;

    /* QEMU should NEVER send the disable command for queue 0 */
    if ((vring_idx == 0 || vring_idx == 1) && !enable) {
        RTE_LOG(ERR, UVHOST, "%s: Can not disable RX/TX queue 0\n", __func__);
        return -1;
    }    

    /*   
     * If the queue is higher than the number supported by vrouter, silently
     * fail here (as there is no error message returned to qemu).
     */
    if ((vring_idx / 2) >= vr_dpdk.nb_fwd_lcores) {
        RTE_LOG(ERR, UVHOST, "%s: Can not %s %s queue %d (only %d queues)\n",
            __func__, enable ? "enable" : "disable",
            (vring_idx & 1) ? "RX" : "TX", vring_idx / 2, 
            vr_dpdk.nb_fwd_lcores);
        return 0;
    }

    vr_uvhost_log("Client %s: setting vif %d vring %u ready state %d\n",
                  uvhm_client_name(vru_cl), vru_cl->vruc_idx, vring_idx, enable);

    // set the appropriate queue to ready state for accepting/sending the
    // packets
    //
    vq_state = enable ? VQ_READY: VQ_NOT_READY;
    if (vr_dpdk_set_virtq_ready(vru_cl->vruc_idx, vring_idx, vq_state)) {
        vr_uvhost_log("Client %s: error setting vring %u ready state\n",
                uvhm_client_name(vru_cl), vring_idx);
        return -1;
    }
        
    return 0;
}

// naren    
static const struct vhost_device_ops dpdk_rte_vhost_device_ops =
{
    .new_device = vr_uvh_new_device_cb,
    .destroy_connection = vr_uvh_destroy_connection_cb,
};

static int
vr_uvh_nl_vif_add_dpdk_handler(vrnu_vif_add_t *msg)
{
    int ret = -1;
    char file_path[VR_UNIX_PATH_MAX];
    uint64_t flags = 0;
    vr_uvh_client_t *vru_cl = NULL;

    if (msg == NULL) {
        vr_uvhost_log("    error adding vif %u: message is NULL\n",
                        msg->vrnu_vif_idx);
        return -1;
    }

    vr_uvhost_log("Adding vif %d virtual device %s\n", msg->vrnu_vif_idx,
                        msg->vrnu_vif_name);

    /* FIXME: workaround for agent issue #1796091
     * Agent sends vhostuser mode as client eventhough
     * its hardcoded in the api-server as server and
     * the port configuration from neutron shows as server.
     * Hardcode it to server mode as we dont use client
     * mode in > 5.x, until agent code is fixed.
     */
    if (msg->vrnu_vif_vhostuser_mode == VRNU_VIF_MODE_CLIENT) {
        msg->vrnu_vif_vhostuser_mode = VRNU_VIF_MODE_SERVER;
        flags |= RTE_VHOST_USER_CLIENT;
    } else {
        flags |= RTE_VHOST_USER_CLIENT;
    }

    if (msg->vrnu_vif_vhostuser_mode == VRNU_VIF_MODE_CLIENT)
        vr_uvhost_log("    vif (client) %u socket %s\n",
                            msg->vrnu_vif_idx, msg->vrnu_vif_name);
    else
        vr_uvhost_log("    vif (server) %u socket %s\n",
                            msg->vrnu_vif_idx, msg->vrnu_vif_name);

    mkdir(vr_socket_dir, VR_DEF_SOCKET_DIR_MODE);
    /* qemu in server mode needs rw access */
    chmod(vr_socket_dir, 0777);
    
    strncpy(file_path, vr_socket_dir, sizeof(file_path) -1);
    strncat(file_path, "/"VR_UVH_VIF_PFX, sizeof(file_path)
        - strlen(file_path) - 1);
    strncat(file_path, msg->vrnu_vif_name,
        sizeof(file_path) - strlen(file_path) - 1);


    ret = rte_vhost_driver_register(file_path, flags);
    if (ret != 0) {
        ret = rte_vhost_driver_unregister(file_path);
        if (ret != 0) {
            vr_uvhost_log("    error unregsiter the driver for %s\n",
                    file_path);
        }
        vr_uvhost_log("    error connecting uvhost socket to %s\n",
                file_path);
        goto error;
    } else {
        // sock_connected = 1;
        vr_uvhost_log("connected to sock    vif %u socket %s FD is %s\n",
                msg->vrnu_vif_idx, msg->vrnu_vif_name, file_path);
    }

    // enable/disable features based on user config
    if (vr_uvhm_enable_disable_features(file_path) < 0) {
            vr_uvhost_log("    error getting features for %s\n",
                    file_path);
            goto error;
    }

    ret = rte_vhost_driver_callback_register(file_path, &dpdk_rte_vhost_device_ops);
    if (ret != 0) {
        vr_uvhost_log("    error registering callback vif %u socket: %s (%d)\n",
                        msg->vrnu_vif_idx, file_path, ret);
        goto error;
    }

    // Naren need to revisit
    vru_cl = vr_uvhost_new_client(1, file_path, msg->vrnu_vif_idx);
    if (vru_cl == NULL) {
        vr_uvhost_log("    error creating vif %u socket %s new vhost client\n",
                      msg->vrnu_vif_idx, file_path);
        goto error;
    }

    vru_cl->vruc_idx = msg->vrnu_vif_idx;
    vru_cl->vruc_flags = flags;
    vru_cl->vruc_vif_gen = msg->vrnu_vif_gen;
    vru_cl->vruc_vhostuser_mode = msg->vrnu_vif_vhostuser_mode;

    vr_dpdk_virtio_set_vif_client(msg->vrnu_vif_idx, vru_cl);
    /* Send netlink interface down message to agent */
    vr_uvh_nl_send_intf_state(0, vru_cl->vruc_idx, basename(vru_cl->vruc_path));
    ret = rte_vhost_driver_start(file_path);
    if (ret < 0) {
        vr_uvhost_log("    error starting vhost drive vif %u socket: %s (%d)\n",
                        msg->vrnu_vif_idx, rte_strerror(errno), errno);
        goto error;
    }

    return 0;

error:
    if (vru_cl) {
        vr_uvhost_del_client(vru_cl);
    }

    return ret;
}

/*
 * vr_uvh_nl_msg_handler - handles messages received form the netlink
 * thread. This is usually to convey the name of the UNIX domain socket
 * that the user space vhost server should listen on for connections from
 * qemu.
 *
 * Returns 0, but logs a message if an error occurs. Returning error would
 * result in connection to netlink being removed from poll().
 */
static int
vr_uvh_nl_msg_handler(int fd, void *arg)
{
    vrnu_msg_t msg;
    int ret;

    ret = recv(fd, (void *) &msg, sizeof(msg), MSG_DONTWAIT);
    if (ret < 0) {
        if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
            vr_uvhost_log("Error %d in netlink msg receive in vhost server\n",
                          errno);
            return 0;
        } else {
            return 0;
        }
    }

    if (ret != sizeof(msg)) {
        vr_uvhost_log("Received msg of length %d, expected %zu in vhost server",
                      ret, sizeof(msg));
        return 0;
    }

    switch (msg.vrnum_type) {
        case VRNU_MSG_VIF_ADD:
            ret = vr_uvh_nl_vif_add_dpdk_handler(&msg.vrnum_vif_add);
            break;

        case VRNU_MSG_VIF_DEL:
            ret = vr_uvh_nl_vif_del_handler(&msg.vrnum_vif_del);
            break;

        default:
            vr_uvhost_log("Unknown netlink msg %d received in vhost server\n",
                          msg.vrnum_type);
            ret = -1;
            break;
    }

    return 0;
}

/*
 * vr_uvh_nl_listen_handler - handles conenctions from the netlink
 * thread.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_uvh_nl_listen_handler(int fd, void *arg)
{
    int s;
    struct sockaddr_un sun;
    socklen_t len = sizeof(sun);

    vr_uvhost_log("Handling connection FD %d...\n", fd);
    s = accept(fd, (struct sockaddr *) &sun, &len);
    if (s < 0) {
        vr_uvhost_log("    error accepting NetLink connection FD %d\n", fd);
        return -1;
    }
    vr_uvhost_log("    FD %d accepted new NetLink connection FD %d\n", fd, s);

    if (vr_uvhost_add_fd(s, UVH_FD_READ, NULL, vr_uvh_nl_msg_handler)) {
        vr_uvhost_log("    error adding socket %s FD %d read handler\n",
                      sun.sun_path, fd);
        return -1;
    }

    return 0;
}
