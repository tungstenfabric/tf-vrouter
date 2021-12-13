/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_INTERFACE_H__
#define __VR_DPDK_N3K_INTERFACE_H__

#include "vr_defs.h"
#include "vr_interface.h"
#include "vr_dpdk.h"

int vr_dpdk_n3k_offload_interface_init(uint16_t count);
void vr_dpdk_n3k_offload_interface_exit(void);

/* Note: Do not persist the returned pointer across the callback boundary. */
const struct vr_interface *vr_dpdk_n3k_offload_interface_get(uint16_t id,struct vr_interface **used_as_virtual);

/* Returns port_id of interface. Assumes vif->vif_os points to non-NULL
 * vr_dpdk_ethdev */
static inline uint16_t
vif_port_id(const struct vr_interface *vif) {
    return ((struct vr_dpdk_ethdev *)vif->vif_os)->ethdev_port_id;
}

/* Note: Do not call this function with offloads spinlock locked, this function
 * will grab that lock by itself */
int vr_dpdk_n3k_offload_interface_add(struct vr_interface *vif);

int vr_dpdk_n3k_offload_interface_del(struct vr_interface *vif);

#endif // __VR_DPDK_N3K_INTERFACE_H__
