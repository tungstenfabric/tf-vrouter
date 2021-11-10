/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_OFFLOAD_ENTRY_H__
#define __VR_DPDK_N3K_OFFLOAD_ENTRY_H__

#include <stdbool.h>
#include <stdint.h>

#include <rte_byteorder.h>

#include "../vr_dpdk_n3k_nexthop.h"
#include "../vr_dpdk_n3k_packet_metadata.h"

struct vr_interface;
struct vr_n3k_offload_vxlan;
struct vr_n3k_offload_flow;
struct vr_dpdk_n3k_packet_metadata;

enum vr_n3k_offload_tunnel_type {
    VR_N3K_OFFLOAD_TUNNEL_NONE,
    VR_N3K_OFFLOAD_TUNNEL_VXLAN,
    VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
    VR_N3K_OFFLOAD_TUNNEL_MPLSOGRE, //unsupported: no hardware support
    VR_N3K_OFFLOAD_TUNNEL_MAX,
};

struct vr_n3k_offload_entry {
    const struct vr_nexthop *src_nh;
    const struct vr_interface *src_vif;
    const struct vr_nexthop *dst_nh;
    const struct vr_interface *dst_vif;
    struct vr_dpdk_n3k_packet_metadata pkt_metadata;
    struct vr_n3k_offload_flow *flow;
    struct vr_n3k_offload_flow *reverse_flow;
    bool route_traffic;
    enum vr_n3k_offload_tunnel_type tunnel_type;
    rte_le32_t tunnel_label;
    const struct vr_interface *mirror_vif;
};

// Returns 0 when execution is successfull.
// Error code is returned when execution fails (-ENOENT, -EINVAL, -ENOSYS).
// It is assumed that offload entry for reverse flow exists.
int
vr_dpdk_n3k_fill_offload_entry(struct vr_n3k_offload_flow* flow,
    struct vr_n3k_offload_entry* entry);

int
vr_dpdk_n3k_fill_offload_entry_partial_start(
    struct vr_n3k_offload_flow* flow,
    struct vr_n3k_offload_entry* entry);
int
vr_dpdk_n3k_fill_offload_entry_vifs(
    struct vr_n3k_offload_entry* entry);
int
vr_dpdk_n3k_fill_offload_entry_partial_end(
    struct vr_n3k_offload_flow* flow,
    struct vr_n3k_offload_entry* entry);

int
vr_dpdk_n3k_fill_offload_entry_for_metadata(
    struct vr_n3k_offload_flow* flow,
    struct vr_n3k_offload_entry* entry);

#endif // __VR_DPDK_N3K_OFFLOAD_ENTRY_H__
