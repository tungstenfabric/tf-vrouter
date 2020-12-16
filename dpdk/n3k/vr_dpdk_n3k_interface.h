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

struct vr_interface;

struct vr_n3k_offload_interface {
    uint16_t id;
    uint16_t type;
    uint32_t flags;
    uint16_t port_id;
    unsigned char mac[VR_ETHER_ALEN];
    uint8_t mirror_id;
};

int vr_dpdk_n3k_offload_interface_init(uint16_t count);
void vr_dpdk_n3k_offload_interface_exit(void);
struct vr_n3k_offload_interface *vr_dpdk_n3k_offload_interface_get(uint16_t id);

void vr_dpdk_n3k_offload_interface_insert(struct vr_n3k_offload_interface *vif);
int vr_dpdk_n3k_offload_interface_add(struct vr_interface *vif);
int vr_dpdk_n3k_offload_interface_del(struct vr_interface *vif);

#endif // __VR_DPDK_N3K_INTERFACE_H__
