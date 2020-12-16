/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_NEXTHOP_H__
#define __VR_DPDK_N3K_NEXTHOP_H__

#include <rte_byteorder.h>
#include "vr_defs.h"

struct vr_nexthop;

struct vr_n3k_offload_nh_label {
    uint32_t nh_idx;
    int label;
};

struct vr_n3k_offload_nexthop {
    uint32_t id;
    uint16_t interface_id;
    uint8_t type;
    uint8_t nh_family;
    uint32_t nh_flags;
    uint32_t vrf;

    uint8_t src_mac[VR_ETHER_ALEN];
    uint8_t dst_mac[VR_ETHER_ALEN];
    rte_be32_t tunnel_src_ip;
    rte_be32_t tunnel_dst_ip;

    uint16_t cnh_cnt;
    struct vr_n3k_offload_nh_label *component_nhs;
};

int vr_dpdk_n3k_offload_nexthop_init(uint32_t count);
void vr_dpdk_n3k_offload_nexthop_exit(void);
struct vr_n3k_offload_nexthop *vr_dpdk_n3k_offload_nexthop_get(uint32_t id);

void vr_dpdk_n3k_offload_nexthop_insert(struct vr_n3k_offload_nexthop *nh);
int vr_dpdk_n3k_offload_nexthop_add(struct vr_nexthop *nh);
int vr_dpdk_n3k_offload_nexthop_del(struct vr_nexthop *nh);
int vr_dpdk_n3k_offload_nexthop_get_cnh_idx(
    const struct vr_n3k_offload_nexthop *nh, uint16_t idx, uint32_t *nh_idx);
int vr_dpdk_n3k_offload_nexthop_get_cnh_label(
    const struct vr_n3k_offload_nexthop *nh, uint16_t idx, uint32_t *label);

#endif // __VR_DPDK_N3K_NEXTHOP_H__
