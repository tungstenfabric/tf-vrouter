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

#include "vr_dpdk.h"

int vr_dpdk_n3k_offload_entry_to_rte_flow_pattern(
    struct vr_n3k_offload_entry *entry, struct rte_flow_item **pattern);

int vr_dpdk_n3k_offload_entry_to_rte_flow_action(
    struct vr_n3k_offload_entry *entry, struct rte_flow_action **actions);

static int
vr_dpdk_n3k_offload_entry_is_valid(struct vr_n3k_offload_entry *entry)
{
    const struct vr_nexthop *src_nh = entry->src_nh;
    const struct vr_interface *src_vif = entry->src_vif;
    const struct vr_nexthop *dst_nh = entry->dst_nh;
    const struct vr_interface *dst_vif = entry->dst_vif;
    const struct vr_n3k_offload_flow *flow = entry->flow;
    const struct vr_dpdk_n3k_packet_metadata *pkt_metadata = &entry->pkt_metadata;

    if (!src_vif || !dst_vif) {
        RTE_LOG(ERR, VROUTER, "%s(): src_vif or dst_vif is NULL\n", __func__);
        return -EINVAL;
    }

    if (!src_nh || !dst_nh) {
        RTE_LOG(ERR, VROUTER, "%s(): src_nh or dst_nh is NULL\n", __func__);
        return -EINVAL;
    }

    if (!pkt_metadata) {
        RTE_LOG(ERR, VROUTER, "%s(): pkt_metadata is NULL\n", __func__);
        return -EINVAL;
    }

    if (!flow) {
        RTE_LOG(ERR, VROUTER, "%s(): flow is NULL\n", __func__);
        return -EINVAL;
    }

    if (src_nh->nh_type != NH_ENCAP && src_nh->nh_type != NH_TUNNEL &&
        src_nh->nh_type != NH_L2_RCV) {
        RTE_LOG(ERR, VROUTER, "%s(): Invalid type of src_nh: %d\n",
            __func__, src_nh->nh_type);
        return -EINVAL;
    }

    if (dst_nh->nh_type != NH_ENCAP && dst_nh->nh_type != NH_TUNNEL) {
        RTE_LOG(ERR, VROUTER, "%s(): Invalid type of dst_nh: %d\n",
            __func__, dst_nh->nh_type);
        return -EINVAL;
    }

    if (src_nh->nh_type == NH_TUNNEL && dst_nh->nh_type == NH_TUNNEL) {
        RTE_LOG(ERR, VROUTER, "%s(): Both NHs are TUNNEL\n", __func__);
        return -EINVAL;
    }

    if (src_nh->nh_type == NH_TUNNEL) {
        if (src_vif->vif_type != VIF_TYPE_PHYSICAL) {
            RTE_LOG(ERR, VROUTER,
                "%s(): src_nh is TUNNEL but vif is not PHY (vif type: %d)\n",
                __func__, src_vif->vif_type);
            return -EINVAL;
        }

        const bool is_mplsoudp = src_nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS;
        const bool is_vxlan = src_nh->nh_flags & NH_FLAG_TUNNEL_VXLAN;
        if (!is_mplsoudp && !is_vxlan) {
            RTE_LOG(ERR, VROUTER,
                "%s(): Only MPLSoUDP and VXLAN tunneling methods are currently supported\n",
                __func__);
            return -ENOTSUP;
        }
    }

    if (src_nh->nh_type == NH_ENCAP && src_vif->vif_type != VIF_TYPE_VIRTUAL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): src_nh is ENCAP but vif is not VIRTUAL (vif type: %d)\n",
            __func__, src_vif->vif_type);
        return -EINVAL;
    }

    if (src_nh->nh_type == NH_L2_RCV && src_vif->vif_type != VIF_TYPE_VIRTUAL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): src_nh is L2_RCV but vif is not VIRTUAL (vif type: %d)\n",
            __func__, src_vif->vif_type);
        return -EINVAL;
    }

    if (dst_nh->nh_type == NH_TUNNEL) {
        if (dst_vif->vif_type != VIF_TYPE_PHYSICAL) {
            RTE_LOG(ERR, VROUTER,
                "%s(): dst_nh is TUNNEL but vif is not PHY (vif type: %d)\n",
                __func__, dst_vif->vif_type);
            return -EINVAL;
        }

        const bool is_mplsoudp = dst_nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS;
        const bool is_vxlan = dst_nh->nh_flags & NH_FLAG_TUNNEL_VXLAN;
        if (!is_mplsoudp && !is_vxlan) {
            RTE_LOG(ERR, VROUTER,
                "%s(): Only MPLSoUDP and VXLAN tunneling methods are currently supported\n",
                __func__);
            return -ENOTSUP;
        }
    }

    if (dst_nh->nh_type == NH_ENCAP && dst_vif->vif_type != VIF_TYPE_VIRTUAL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): dst_nh is ENCAP but vif is not VIRTUAL (vif type: %d)\n",
            __func__, dst_vif->vif_type);
        return -EINVAL;
    }

    if (src_nh->nh_type == NH_ENCAP && !pkt_metadata->eth_hdr_present) {
        RTE_LOG(ERR, VROUTER,
            "%s(): src_nh is ENCAP but ETH header is not present\n", __func__);
        return -EINVAL;
    }

    if (dst_nh->nh_type == NH_TUNNEL || src_nh->nh_type == NH_TUNNEL) {
        if (entry->tunnel_type == VR_N3K_OFFLOAD_TUNNEL_NONE) {
            RTE_LOG(ERR, VROUTER,
                "%s(): One of the NHs is TUNNEL but tunnel_type is NONE\n",
                __func__);
            return -EINVAL;
        }
    } else {
        if (entry->tunnel_type != VR_N3K_OFFLOAD_TUNNEL_NONE) {
            RTE_LOG(ERR, VROUTER,
                "%s(): None of the NHs is TUNNEL but tunnel_type is set to: %d\n",
                __func__, entry->tunnel_type);
            return -EINVAL;
        }
    }

    if (flow->action != VR_FLOW_ACTION_FORWARD &&
            flow->action != VR_FLOW_ACTION_NAT &&
            flow->action != VR_FLOW_ACTION_DROP) {
        RTE_LOG(ERR, VROUTER, "%s(): Invalid flow action: %d\n",
            __func__, flow->action);
        return -EINVAL;
    }

    if (flow->action == VR_FLOW_ACTION_NAT && !entry->reverse_flow) {
        RTE_LOG(ERR, VROUTER,
            "%s(): The flow action is NAT but reverse flow is not set\n",
            __func__);
        return -EINVAL;
    }

    const bool is_nat_flag_set =
        (flow->flags & VR_FLOW_FLAG_SNAT) | (flow->flags & VR_FLOW_FLAG_DNAT);
    if (flow->action == VR_FLOW_ACTION_NAT && !is_nat_flag_set) {
        RTE_LOG(ERR, VROUTER,
            "%s(): The flow action is NAT but NAT flag is not set\n", __func__);
        return -EINVAL;
    }

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
    if (ret) {
        RTE_LOG(ERR, VROUTER, "%s(): offload_entry validation failed: %d\n",
            __func__, ret);
        goto exit;
    }

    ret = vr_dpdk_n3k_offload_entry_to_rte_flow_pattern(
        entry, &flow_package.pattern);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Conversion of offload_entry to rte_flow pattern failed: %d\n",
            __func__, ret);
        goto exit;
    }

    ret = vr_dpdk_n3k_offload_entry_to_rte_flow_action(
        entry, &flow_package.actions);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Conversion of offload_entry to rte_flow action failed: %d\n",
            __func__, ret);
        goto exit;
    }

exit:
    flow_package.error = ret;
    return flow_package;
}
