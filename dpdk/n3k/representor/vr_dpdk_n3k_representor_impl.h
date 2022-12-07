/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_REPRESENTOR_IMPL_H__
#define __VR_DPDK_N3K_REPRESENTOR_IMPL_H__

#include <vr_dpdk.h>
#include <vr_interface.h>

enum vr_dpdk_n3k_datapath_type {
    N3K_DATAPATH_DETERMINISTIC_UNVERIFIED = 0,
    N3K_DATAPATH_DETERMINISTIC_PCI_PASSTHRU,
    N3K_DATAPATH_DETERMINISTIC_VDPA,
    N3K_DATAPATH_MAPPED_VDPA,
    N3K_DATAPATH_NO_VDPA_VHOST_USER, //not a representor
    N3K_DATAPATH_UNKNOWN //not a representor
};

#define VR_UVH_VIF_PFX "uvh_vif_"

enum {VIRTIO_RXQ, VIRTIO_TXQ, VIRTIO_QNUM};

//queue
int vr_dpdk_n3k_representor_queue_setup(struct vr_dpdk_ethdev *ethdev);
int vr_dpdk_n3k_representor_queue_lcore_interconnect(struct vr_interface *vif,
    const char *repr_name);
void vr_dpdk_n3k_representor_queue_lcore_disconnect(struct vr_interface *vif);

//datapath
enum vr_dpdk_n3k_datapath_type
vr_dpdk_n3k_datapath_deduce(struct vr_interface *, const char **);
int vr_dpdk_n3k_datapath_setup(struct vr_interface *, const char *);
void vr_dpdk_n3k_datapath_teardown(struct vr_interface *);

//map
const char *vr_dpdk_n3k_representor_map_create_mapping(struct vr_interface *);
void vr_dpdk_n3k_representor_map_delete_mapping(struct vr_interface *);
int vr_dpdk_n3k_representor_map_init(void);
void vr_dpdk_n3k_representor_map_exit(void);

//link
void vr_dpdk_n3k_link_init(void);
void vr_dpdk_n3k_link_exit(void);
void vr_dpdk_n3k_link_intr_setup(struct vr_dpdk_ethdev *ethdev);

//ethdev
int vr_dpdk_n3k_representor_ethdev_release(struct vr_interface *);
int vr_dpdk_n3k_representor_ethdev_init(struct vr_interface *, const char *, uint16_t);

//vhost
int vr_dpdk_n3k_vhost_register(struct vr_interface *vif, uint32_t vif_vdpa_did);
void vr_dpdk_n3k_vhost_unregister(struct vr_interface *vif);
int vr_dpdk_n3k_vhost_init(void);
void vr_dpdk_n3k_vhost_exit(void);

#endif /* __VR_DPDK_N3K_REPRESENTOR_IMPL_H__ */
