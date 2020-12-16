/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_VXLAN_H__
#define __VR_DPDK_N3K_VXLAN_H__

#include <rte_byteorder.h>
#include "vr_defs.h"

struct vr_nexthop;

struct vr_n3k_offload_vxlan {
    rte_le32_t vnid;
    uint32_t nexthop_id;
};

int vr_dpdk_n3k_offload_vxlan_init(uint32_t nh_count);
void vr_dpdk_n3k_offload_vxlan_exit(void);
struct vr_n3k_offload_vxlan *vr_dpdk_n3k_offload_vxlan_get_by_vni(uint32_t vnid);
struct vr_n3k_offload_vxlan *vr_dpdk_n3k_offload_vxlan_get_by_nh(uint32_t nh_id);

void vr_dpdk_n3k_offload_vxlan_insert(struct vr_n3k_offload_vxlan *vxlan);
int vr_dpdk_n3k_offload_vxlan_add(struct vr_nexthop *nh, int vnid);
int vr_dpdk_n3k_offload_vxlan_del(int vnid);

#endif // __VR_DPDK_N3K_VXLAN_H__
