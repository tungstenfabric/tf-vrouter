/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_offload_converter.h"
#include "vr_dpdk_n3k_offload_entry.h"

#include "../vr_dpdk_n3k_flow.h"
#include "../vr_dpdk_n3k_interface.h"
#include "../vr_dpdk_n3k_nexthop.h"
#include "../vr_dpdk_n3k_packet_metadata.h"

#include <vr_packet.h>
#include <vr_nexthop.h>
#include <vr_interface.h>

int vr_dpdk_n3k_offload_entry_to_rte_flow_pattern(
    struct vr_n3k_offload_entry *entry, struct rte_flow_item **pattern);

int vr_dpdk_n3k_offload_entry_to_rte_flow_action(
    struct vr_n3k_offload_entry *entry, struct rte_flow_action **actions);

static int
vr_dpdk_n3k_offload_entry_is_valid(struct vr_n3k_offload_entry *entry)
{
    const struct vr_n3k_offload_nexthop *src_nh = entry->src_nh;
    const struct vr_n3k_offload_interface *src_vif = entry->src_vif;
    const struct vr_n3k_offload_nexthop *dst_nh = entry->dst_nh;
    const struct vr_n3k_offload_interface *dst_vif = entry->dst_vif;
    const struct vr_n3k_offload_flow *flow = entry->flow;
    const struct vr_dpdk_n3k_packet_metadata *pkt_metadata = &entry->pkt_metadata;

    /* TODO(n3k): Add logs */

    if (!src_vif || !dst_vif)
        return -EINVAL;

    if (!src_nh || !dst_nh)
        return -EINVAL;

    if (!pkt_metadata)
        return -EINVAL;

    if (!flow)
        return -EINVAL;

    if (src_nh->type != NH_ENCAP && src_nh->type != NH_TUNNEL &&
        src_nh->type != NH_L2_RCV)
        return -EINVAL;

    if (dst_nh->type != NH_ENCAP && dst_nh->type != NH_TUNNEL)
        return -EINVAL;

    if (src_nh->type == NH_TUNNEL && dst_nh->type == NH_TUNNEL)
        return -EINVAL;

    if (src_nh->type == NH_TUNNEL && src_vif->type != VIF_TYPE_PHYSICAL)
        return -EINVAL;

    if (src_nh->type == NH_ENCAP && src_vif->type != VIF_TYPE_VIRTUAL)
        return -EINVAL;

    if (src_nh->type == NH_L2_RCV && src_vif->type != VIF_TYPE_VIRTUAL)
        return -EINVAL;

    if (dst_nh->type == NH_TUNNEL && dst_vif->type != VIF_TYPE_PHYSICAL)
        return -EINVAL;

    if (dst_nh->type == NH_ENCAP && dst_vif->type != VIF_TYPE_VIRTUAL)
        return -EINVAL;

    if (src_nh->type == NH_ENCAP && !pkt_metadata->eth_hdr_present)
        return -EINVAL;

    if (dst_nh->type == NH_TUNNEL || src_nh->type == NH_TUNNEL) {
        if (entry->tunnel_type == VR_N3K_OFFLOAD_TUNNEL_NONE) {
            return -EINVAL;
        }
    } else {
        if (entry->tunnel_type != VR_N3K_OFFLOAD_TUNNEL_NONE) {
            return -EINVAL;
        }
    }

    if (flow->action != VR_FLOW_ACTION_FORWARD &&
            flow->action != VR_FLOW_ACTION_NAT &&
            flow->action != VR_FLOW_ACTION_DROP)
        return -EINVAL;

    if (flow->action == VR_FLOW_ACTION_NAT && !entry->reverse_flow)
        return -EINVAL;

    const bool is_nat_flag_set =
        (flow->flags & VR_FLOW_FLAG_SNAT) | (flow->flags & VR_FLOW_FLAG_DNAT);
    if (flow->action == VR_FLOW_ACTION_NAT && !is_nat_flag_set)
        return -EINVAL;

    return 0;
}

struct vr_n3k_rte_flow_package
vr_dpdk_n3k_offload_entry_to_rte_flow(struct vr_n3k_offload_entry *entry)
{
    int ret = 0;
    struct vr_n3k_rte_flow_package flow_package = {
        .error = 0,
        .pattern = NULL,
        .actions = NULL,
    };

    ret = vr_dpdk_n3k_offload_entry_is_valid(entry);
    if (ret)
        goto exit;

    ret = vr_dpdk_n3k_offload_entry_to_rte_flow_pattern(
        entry, &flow_package.pattern);
    if (ret)
        goto exit;

    ret = vr_dpdk_n3k_offload_entry_to_rte_flow_action(
        entry, &flow_package.actions);
    if (ret)
        goto exit;

exit:
    flow_package.error = ret;
    return flow_package;
}
