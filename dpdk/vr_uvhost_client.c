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

    if (vr_uvh_clients[cidx].vruc_vid != -1) {
        vr_uvhost_log("    Error accessing existing vhost device %d, %d\n",
                cidx, vr_uvh_clients[cidx].vruc_vid);
        return NULL;
    }

    strncpy(vr_uvh_clients[cidx].vruc_path, path, VR_UNIX_PATH_MAX - 1);
    vr_uvh_clients[cidx].vruc_flags = 0;

    return &vr_uvh_clients[cidx];
}

vr_uvh_client_t * 
vr_uvhost_update_client(int vid, char *path)
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
        vr_uvhost_log("    error in client cidx = %d, %d\n",
                cidx, vr_uvh_clients[cidx].vruc_idx);
        return NULL;
    }

    if (vr_uvh_clients[cidx].vruc_vid < 0) {
        vr_uvh_clients[cidx].vruc_vid = vid;
        vr_uvh_vhost_devices[vid] = cidx;
    } else {
        // error
        vr_uvhost_log("    error setting vid = %d, %d\n",
                vid, vr_uvh_clients[cidx].vruc_vid);

        return NULL;
    }

    return &vr_uvh_clients[cidx];
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
