/*
 * vr_uvhost_client.h - header file for client state handling in user
 * space vhost server that peers with the vhost client inside qemu (version
 * 2.1 and later).
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_UVHOST_CLIENT_H__
#define __VR_UVHOST_CLIENT_H__

/*
 * VR_UVH_MAX_CLIENTS needs to be the same as VR_MAX_INTERFACES.
 */
#define VR_UVH_MAX_CLIENTS VR_MAX_INTERFACES

typedef enum vr_uvh_client_ready_state {
    VR_CLIENT_NOT_READY,
    VR_CLIENT_PENDING_READY,
    VR_CLIENT_READY,
} vr_uvh_client_state_t;

typedef struct vr_uvh_client {
    char vruc_path[VR_UNIX_PATH_MAX];
    uint8_t      vruc_state;
    unsigned int vruc_idx;
    int          vruc_vid;
    unsigned int vruc_vif_gen;
    unsigned int vruc_vhostuser_mode;
    unsigned int vruc_flags;
#define VRUC_FLAG_SET_FEATURE_DONE 0x0001
    pthread_t vruc_owner;
} vr_uvh_client_t;

void vr_uvhost_client_init(void);
vr_uvh_client_t *vr_uvhost_new_client(int fd, char *path, int cidx);
void vr_uvhost_del_client(vr_uvh_client_t *vru_cl);
vr_uvh_client_t *vr_uvhost_get_client(unsigned int cidx);
vr_uvh_client_t *vr_uvhost_get_vhost_client(int vid);
vr_uvh_client_t *vr_uvhost_update_client(int vid, char *path, vr_uvh_client_state_t state);
#endif /* __VR_UVHOST_CLIENT_H__ */

