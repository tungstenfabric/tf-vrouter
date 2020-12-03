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
#include "nl_util.h"
#include <rte_vhost.h>

static vr_uvh_client_t vr_uvh_clients[VR_UVH_MAX_CLIENTS];
/*
 * vr_uvhost_client_init - initialize the client array.
 */
void
vr_uvhost_client_init(void)
{
    int i;

    for (i = 0; i < VR_UVH_MAX_CLIENTS; i++) {
        vr_uvh_clients[i].vruc_vid = -1;
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
vr_uvhost_new_client(char *path, int cidx)
{
    if (cidx >= VR_UVH_MAX_CLIENTS) {
        return NULL;
    }

    strncpy(vr_uvh_clients[cidx].vruc_path, path, VR_UNIX_PATH_MAX - 1);
    vr_uvh_clients[cidx].vruc_flags = 0;

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

vr_uvh_client_t *
vr_uvhost_get_client_from_vid(int vid)
{
    int i;
    char ifname[VR_UNIX_PATH_MAX];

    rte_vhost_get_ifname(vid, ifname, sizeof(ifname));

    for (i = 0; i < VR_UVH_MAX_CLIENTS; i++) {
        if(strncmp(vr_uvh_clients[i].vruc_path, ifname, strlen(ifname)) == 0) {
            return &vr_uvh_clients[i];
        }
    }
    return NULL;
}
