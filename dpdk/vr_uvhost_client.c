/*
 * vr_uvhost_client.c - client handling in user space vhost server that
 * peers with the vhost client inside qemu (version 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_dpdk.h"
#include "vr_uvhost_client.h"
#include "vr_uvhost_util.h"
#include "vr_uvhost_msg.h"


static vr_uvh_client_t vr_uvh_clients[VR_UVH_MAX_CLIENTS];
static int vr_uvh_vhost_devices[VR_UVH_MAX_CLIENTS];

/*
 * vr_uvhost_client_init - initialize the client array.
 */
void
vr_uvhost_client_init(void)
{
    int i;

    for (i = 0; i < VR_UVH_MAX_CLIENTS; i++) {
        vr_uvh_clients[i].vruc_vid = -1;
        vr_uvh_clients[i].vruc_state = VR_CLIENT_NOT_READY;
        vr_uvh_vhost_devices[i] = -1;
    }

    return;
}

/*
 * vr_uvhost_new_client - initializes state for a new user space vhost client
 * FD is a file descriptor for the client socket. path is the UNIX domain
 * socket path. cidx is the index of the client.
 *
 * Returns a pointer to the client state on success, NULL otherwise.
 */
vr_uvh_client_t *
vr_uvhost_new_client(int fd, char *path, int cidx)
{
    if (cidx >= VR_UVH_MAX_CLIENTS) {
        return NULL;
    }

    if (vr_uvh_clients[cidx].vruc_state != VR_CLIENT_NOT_READY) {
        return NULL;
    }
    vr_uvh_clients[cidx].vruc_state = VR_CLIENT_PENDING_READY;

    strncpy(vr_uvh_clients[cidx].vruc_path, path, VR_UNIX_PATH_MAX - 1);
    vr_uvh_clients[cidx].vruc_flags = 0;

    return &vr_uvh_clients[cidx];
}

vr_uvh_client_t * 
vr_uvhost_update_client(int vid, char *path, vr_uvh_client_state_t state)
{
    int cidx;

    // lookup for cidx in the list
    for (cidx = 0; cidx < VR_UVH_MAX_CLIENTS; cidx++) {
        if (strncmp(vr_uvh_clients[cidx].vruc_path, path, VR_UNIX_PATH_MAX-1) == 0) {
            // found client!
            break;
        }
    }
    if (cidx >= VR_UVH_MAX_CLIENTS) {
        // error not found fatal ??
        return NULL;
    }

    if (vr_uvh_clients[cidx].vruc_idx != cidx) {
        // error
    vr_uvhost_log("    NAREN error in cidx = %d, %d\n",
                            cidx, vr_uvh_clients[cidx].vruc_idx);
        return NULL;
    }

    if (state == VR_CLIENT_READY) {
        if (vr_uvh_clients[cidx].vruc_vid < 0) {
    vr_uvhost_log("    NAREN setting client in cidx = %d, %d\n",
                            cidx, vr_uvh_clients[cidx].vruc_vid);
            vr_uvh_clients[cidx].vruc_vid = vid;
            vr_uvh_vhost_devices[vid] = cidx;
        } else {
            // error
    vr_uvhost_log("    NAREN NAREN error setting vid = %d, %d\n",
                            vid, vr_uvh_clients[cidx].vruc_vid);
            
            return NULL;
        }
    } else {
        vr_uvh_vhost_devices[vid] = -1;
    }
    vr_uvh_clients[cidx].vruc_state = state;

    return &vr_uvh_clients[cidx];
}


/*
 * vr_uvhost_del_client - removes a vhost client.
 *
 * Returns nothing.
 */
void
vr_uvhost_del_client(vr_uvh_client_t *vru_cl)
{
#if 0
    /* Remove both the socket we listen for and the socket we have accepted */
    vr_uvhost_del_fds_by_arg(vru_cl);

    /* If a VIF is added but not connected, vru_cl->vruc_fd is not added to
     * the fd list even though it is created. This can happen when VM is
     * stopped. In this case, vr_uvhost_del_fds_by_arg() would not close
     * the fd. So, add the fcntl() call below to check if vruc_fd is closed
     * or not.
     * */
    if(fcntl(vru_cl->vruc_fd, F_GETFL) != -1 ){
            vr_uvhost_log("Closing socket fd: %d \n", vru_cl->vruc_fd);
            close(vru_cl->vruc_fd);
    }

    vru_cl->vruc_fd = -1;
#endif
    if (vru_cl->vruc_vhostuser_mode == VRNU_VIF_MODE_CLIENT)
        unlink(vru_cl->vruc_path);
    vru_cl->vruc_flags = 0;

    return;
}

/*
 * vr_uvhost_get_client - Returns the client at the specified index, NULL if
 * it cannot be found.
 */
vr_uvh_client_t *
vr_uvhost_get_client(unsigned int cidx)
{
    if (cidx >= VR_UVH_MAX_CLIENTS) {
        return NULL;
    }

    return &vr_uvh_clients[cidx];
}

/*
 * vr_uvhost_get_client - Returns the client at the specified index, NULL if
 * it cannot be found.
 */
vr_uvh_client_t *
vr_uvhost_get_vhost_client(int vid)
{
    int cidx;

    if (vid >= VR_UVH_MAX_CLIENTS) {
        return NULL;
    }
    
    cidx = vr_uvh_vhost_devices[vid];
    if (cidx < 0) { 
        return NULL;
    }

    return &vr_uvh_clients[cidx];
}
