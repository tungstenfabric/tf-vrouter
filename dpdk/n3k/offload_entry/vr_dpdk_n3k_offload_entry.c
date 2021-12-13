/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_offload_entry.h"

#include <rte_log.h>

#include <vr_nexthop.h>
#include <vr_vxlan.h>
#include <vr_interface.h>
#include <vr_mirror.h>
#include <vr_dpdk.h>

#include "../vr_dpdk_n3k_flow.h"
#include "../vr_dpdk_n3k_interface.h"
#include "../vr_dpdk_n3k_nexthop.h"
#include "../vr_dpdk_n3k_missing_mirror.h"
#include "../vr_dpdk_n3k_mpls.h"
#include "../vr_dpdk_n3k_packet_metadata.h"
#include "../vr_dpdk_n3k_routes.h"
#include "../vr_dpdk_n3k_vxlan.h"

// Returns positive value when execution is successful.
static int
set_reverse_flow_offload(struct vr_n3k_offload_entry* entry)
{
    struct vr_n3k_offload_flowtable_key key;
    memset(&key, 0, sizeof(key));
    key.fe_index = entry->flow->reverse_id;
    entry->reverse_flow = vr_dpdk_n3k_offload_flow_get(&key);
    if (entry->reverse_flow == NULL) {
        RTE_LOG(ERR, VROUTER, "set_reverse_flow_offload: "
            "vr_dpdk_n3k_flow_get failed for fe_index == %d.\n",
            key.fe_index);
        return -ENOENT;
    }
    return 0;
}

// Returns positive value when execution is successful.
static int
set_packet_metadata(struct vr_n3k_offload_entry* entry)
{
    if (!entry->flow) {
        return -EINVAL;
    }

    int ret = vr_dpdk_n3k_packet_metadata_find_by_flow(
        entry->flow, &entry->pkt_metadata);

    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): vr_dpdk_n3k_packet_metadata_find failed.\n",
            __FUNCTION__);
        return ret;
    }

    return 0;
}

// Returns 0 when execution is successful.
static int
copy_overlay_src_mac_from_pkt_metadata(
    struct vr_dpdk_n3k_packet_metadata *pkt_metadata,
    uint8_t *mac)
{
    if (!pkt_metadata->eth_hdr_present) {
        RTE_LOG(ERR, VROUTER, "%s(): "
            "Inner eth header was not present in metadata.\n", __func__);
        return -EINVAL;
    }

    memcpy(mac, pkt_metadata->inner_src_mac, VR_ETHER_ALEN);
    return 0;
}

// Returns 0 when execution is successful.
static int
copy_overlay_dst_mac_from_pkt_metadata(
    struct vr_dpdk_n3k_packet_metadata *pkt_metadata,
    uint8_t *mac)
{
    if (!pkt_metadata->eth_hdr_present) {
        RTE_LOG(ERR, VROUTER, "%s(): "
            "Inner eth header was not present in metadata.\n", __func__);
        return -EINVAL;
    }

    memcpy(mac, pkt_metadata->inner_dst_mac, VR_ETHER_ALEN);
    return 0;
}

// Returns 0 when execution is successful.
static int
set_src_nh_l2(struct vr_n3k_offload_entry* entry)
{
    struct vr_n3k_offload_bridge_key bridge_key_for_src_nh;
    memset(&bridge_key_for_src_nh, 0, sizeof(bridge_key_for_src_nh));
    bridge_key_for_src_nh.vrf_id = entry->flow->src_vrf_id;
    int ret = copy_overlay_src_mac_from_pkt_metadata(
        &entry->pkt_metadata, bridge_key_for_src_nh.mac);
    if (ret < 0) return ret;

    struct vr_n3k_offload_bridge_value bridge_value;
    ret = vr_dpdk_n3k_offload_bridge_find(
        &bridge_key_for_src_nh, &bridge_value);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "set_src_nh_l2: "
            "vr_dpdk_n3k_offload_bridge_find failed; vrf=%d; mac=" MAC_FORMAT ".\n",
            bridge_key_for_src_nh.vrf_id, MAC_VALUE(bridge_key_for_src_nh.mac));
        return ret;
    }

    uint32_t src_nh_id = bridge_value.nh_id;

    const struct vr_nexthop *src_offload_nexthop =
        vr_dpdk_n3k_offload_nexthop_get(src_nh_id);
    if (src_offload_nexthop == NULL) {
        RTE_LOG(ERR, VROUTER, "set_src_nh_l2: src_offload_nexthop == NULL"
            " for src_nh_id == %d.\n", src_nh_id);
        return -ENOENT;
    }
    entry->src_nh = src_offload_nexthop;

    return 0;
}

int
find_bridge_value_for_src_overlay_mac_in_bridge_table(
    struct vr_n3k_offload_entry *entry,
    struct vr_n3k_offload_bridge_value *bridge_value)
{
    struct vr_n3k_offload_bridge_key bridge_key_for_src_nh;
    memset(&bridge_key_for_src_nh, 0, sizeof(bridge_key_for_src_nh));
    bridge_key_for_src_nh.vrf_id = entry->flow->src_vrf_id;
    int ret = copy_overlay_src_mac_from_pkt_metadata(
        &entry->pkt_metadata, bridge_key_for_src_nh.mac);
    if (ret < 0) return ret;

    ret = vr_dpdk_n3k_offload_bridge_find(
        &bridge_key_for_src_nh, bridge_value);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "find_bridge_value_for_src_overlay_mac_in_"
            "bridge_table: vr_dpdk_n3k_offload_bridge_find failed for "
            "VRF=%d and MAC=" MAC_FORMAT ".\n",
            bridge_key_for_src_nh.vrf_id,
            MAC_VALUE(bridge_key_for_src_nh.mac));
    }
    return ret;
}

int
find_bridge_value_for_dst_overlay_mac_in_bridge_table(
    struct vr_n3k_offload_entry *entry,
    struct vr_n3k_offload_bridge_value *bridge_value)
{
    struct vr_n3k_offload_bridge_key bridge_key_for_dst_nh;
    memset(&bridge_key_for_dst_nh, 0, sizeof(bridge_key_for_dst_nh));
    bridge_key_for_dst_nh.vrf_id = entry->flow->src_vrf_id;
    int ret = copy_overlay_dst_mac_from_pkt_metadata(
        &entry->pkt_metadata, bridge_key_for_dst_nh.mac);
    if (ret < 0) return ret;

    ret = vr_dpdk_n3k_offload_bridge_find(
        &bridge_key_for_dst_nh, bridge_value);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "find_bridge_value_for_dst_overlay_mac_in_"
            "bridge_table: vr_dpdk_n3k_offload_bridge_find failed for "
            "VRF=%d and MAC=" MAC_FORMAT ".\n",
            bridge_key_for_dst_nh.vrf_id,
            MAC_VALUE(bridge_key_for_dst_nh.mac));
    }
    return ret;
}

static int
find_route_value_for_dst_overlay_ip_in_route_table(
    const struct vr_n3k_offload_entry *entry,
    struct vr_n3k_offload_route_value *route_value)
{
    struct vr_n3k_offload_route_key key = {
        .vrf_id = entry->flow->src_vrf_id,
        .type = entry->flow->ip.type,
        .ip = entry->flow->ip.dst
    };

    int ret = vr_dpdk_n3k_offload_route_find(key, route_value);

    if (ret) {
        RTE_LOG(ERR, VROUTER, "%s: vr_dpdk_n3k_offload_route_find failed for "
            "VRF=%d and IP=" IPV4_FORMAT ".\n",
            __FUNCTION__, key.vrf_id,
            IPV4_VALUE(&key.ip));
    }

    return ret;
}

// Returns NULL when lookup fails.
const struct vr_nexthop *
find_nexthop_for_dst_overlay_mac_in_bridge_table(
    struct vr_n3k_offload_entry* entry)
{
    struct vr_n3k_offload_bridge_value bridge_value;
    int ret = find_bridge_value_for_dst_overlay_mac_in_bridge_table(
        entry, &bridge_value);
    if (ret < 0)
        return NULL;
    uint32_t dst_nh_id = bridge_value.nh_id;

    const struct vr_nexthop *dst_offload_nexthop =
        vr_dpdk_n3k_offload_nexthop_get(dst_nh_id);
    if (dst_offload_nexthop == NULL) {
        RTE_LOG(ERR, VROUTER, "find_nexthop_for_dst_overlay_mac_in_bridge_"
            "table: vr_dpdk_n3k_offload_nexthop_get failed for"
            " dst_nh_id == %d.\n", dst_nh_id);
    }

    return dst_offload_nexthop;
}

enum lookup_type { LOOKUP_MIN_NH, LOOKUP_SRC_NH, LOOKUP_DST_NH, LOOKUP_MAX_NH };

const struct vr_nexthop *
find_nexthop_for_overlay_ip_in_route_table(struct vr_n3k_offload_entry *entry,
    enum lookup_type type)
{
    assert(type == LOOKUP_SRC_NH || type == LOOKUP_DST_NH);

    struct vr_n3k_offload_route_key key = {
        .type = entry->flow->ip.type,
        .vrf_id = entry->flow->src_vrf_id,
        .ip = type == LOOKUP_SRC_NH
            ? entry->flow->ip.src
            : entry->flow->ip.dst
    };

    struct vr_n3k_offload_route_value route_value;

    if (vr_dpdk_n3k_offload_route_find(key, &route_value) < 0) {
        RTE_LOG(ERR, VROUTER, "%s: vr_dpdk_n3k_offload_route_find failed for "
            "VRF=%d and IP=" IPV4_FORMAT ".\n",
            __FUNCTION__, key.vrf_id, IPV4_VALUE(&key.ip));
        return NULL;
    }

    const struct vr_nexthop *offload_nexthop =
        vr_dpdk_n3k_offload_nexthop_get(route_value.nh_id);
    if (offload_nexthop == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s: vr_dpdk_n3k_offload_nexthop_get failed for "
            "VRF=%d and IP=" IPV4_FORMAT ".\n",
            __FUNCTION__, key.vrf_id, IPV4_VALUE(&key.ip));
        return NULL;
    }

    return offload_nexthop;
}


static int
fill_label_in_entry_from_composite_nh(struct vr_n3k_offload_entry *entry,
    const struct vr_nexthop *offload_nexthop)
{
    int8_t ecmp_nh_idx = entry->flow->ecmp_nh_idx;

    int ret = vr_dpdk_n3k_offload_nexthop_get_cnh_label(
        offload_nexthop, ecmp_nh_idx, &entry->tunnel_label);

    return ret;
}


static int
vr_dpdk_n3k_offload_entry_fill_mpls_l2(struct vr_n3k_offload_entry* entry)
{
    struct vr_n3k_offload_bridge_value bridge_value;
    if (find_bridge_value_for_dst_overlay_mac_in_bridge_table(
            entry, &bridge_value) < 0) {
        return -EINVAL;
    }

    const struct vr_nexthop *nh = vr_dpdk_n3k_offload_nexthop_get(bridge_value.nh_id);


    if (nh == NULL)
        return -EINVAL;

    entry->tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP;

    if (nh->nh_type == NH_COMPOSITE)
        return fill_label_in_entry_from_composite_nh(entry, nh);

    entry->tunnel_label = bridge_value.label;
    return 0;
}

static int
vr_dpdk_n3k_offload_entry_fill_mpls_l3(struct vr_n3k_offload_entry* entry)
{
    int ret;
    struct vr_n3k_offload_route_value route_value;

    if ((ret = find_route_value_for_dst_overlay_ip_in_route_table(
             entry, &route_value)) < 0) {
        return ret;
    }

    const struct vr_nexthop *nh = vr_dpdk_n3k_offload_nexthop_get(route_value.nh_id);

    if (nh == NULL)
        return -EINVAL;

    entry->tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP;

    if (nh->nh_type == NH_COMPOSITE)
        return fill_label_in_entry_from_composite_nh(entry, nh);

    entry->tunnel_label = route_value.label;
    return 0;
}

static const struct vr_nexthop *
choose_component_nh(struct vr_n3k_offload_entry *entry,
    const struct vr_nexthop *offload_nexthop)
{
    int8_t ecmp_nh_idx = entry->flow->ecmp_nh_idx;
    uint32_t cnh_idx;

    int ret = vr_dpdk_n3k_offload_nexthop_get_cnh_idx(
        offload_nexthop, ecmp_nh_idx, &cnh_idx);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Getting component NH id failed for NH id=%d, ecmp_idx=%d, ret=%d\n",
            __FUNCTION__, offload_nexthop->nh_id, ecmp_nh_idx, ret);
        return NULL;
    }

    offload_nexthop = vr_dpdk_n3k_offload_nexthop_get(cnh_idx);
    if (offload_nexthop == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Getting NH failed for NH id=%d for composite NH id=%d, ecmp_idx=%d\n",
            __FUNCTION__, cnh_idx, offload_nexthop->nh_id, ecmp_nh_idx);
    }
    return offload_nexthop;
}

static int
set_src_nh_l3(struct vr_n3k_offload_entry *entry)
{
    // MPLSoUDP L3
    const struct vr_nexthop *src_offload_nexthop;

    if ((src_offload_nexthop = find_nexthop_for_overlay_ip_in_route_table(
              entry, LOOKUP_SRC_NH)) == NULL) {
        char addr[40];
        RTE_LOG(ERR, VROUTER,
            "%s(): src_offload_nexthop == NULL for ip == %s.\n",
            __FUNCTION__,
            vr_dpdk_n3k_convert_ip_to_str(addr, &entry->flow->ip.src,
                                entry->flow->ip.type));
        return -ENOENT;
    }

    entry->src_nh = src_offload_nexthop;
    return 0;
}

static int
set_src_nh(struct vr_n3k_offload_entry *entry)
{
    if (entry->route_traffic) {
        return set_src_nh_l3(entry);
    } else {
        return set_src_nh_l2(entry);
    }
}


static int
fill_dst_nh_in_entry(struct vr_n3k_offload_entry *entry,
    const struct vr_nexthop *dst_offload_nexthop)
{
    if (dst_offload_nexthop->nh_type == NH_COMPOSITE) {
        dst_offload_nexthop = choose_component_nh(
            entry, dst_offload_nexthop);
        if (dst_offload_nexthop == NULL) {
            return -ENOENT;
        }
    }

    if (dst_offload_nexthop->nh_type == NH_ENCAP ||
            dst_offload_nexthop->nh_type == NH_TUNNEL) {
        entry->dst_nh = dst_offload_nexthop;
    } else {
        // We do not provide offloading capability for this case.
        RTE_LOG(ERR, VROUTER,
            "%s(): Invalid destination NH type: %d\n",
            __FUNCTION__, dst_offload_nexthop->nh_type);
        return -EINVAL;
    }
    return 0;
}


static int
set_dst_nh_l3(struct vr_n3k_offload_entry *entry)
{
    entry->route_traffic = true;

    const struct vr_nexthop *dst_offload_nexthop =
        find_nexthop_for_overlay_ip_in_route_table(entry, LOOKUP_DST_NH);
    if (dst_offload_nexthop == NULL)
        return -ENOENT;

    return fill_dst_nh_in_entry(entry, dst_offload_nexthop);
}

static int
set_dst_nh(struct vr_n3k_offload_entry *entry)
{
    entry->route_traffic = false;

    if (entry->pkt_metadata.eth_hdr_present) {
        const struct vr_nexthop *dst_offload_nexthop =
            find_nexthop_for_dst_overlay_mac_in_bridge_table(entry);

        if (dst_offload_nexthop == NULL)
            return -ENOENT;

        if (dst_offload_nexthop->nh_type == NH_L2_RCV)
        {
            return set_dst_nh_l3(entry);
        }
        return fill_dst_nh_in_entry(entry, dst_offload_nexthop);
    } else {
        return set_dst_nh_l3(entry);
    }
}

// Returns 0 when execution is successful.
static int
set_nh(struct vr_n3k_offload_entry *entry)
{
    int ret;

    if ((ret = set_dst_nh(entry)) < 0) {
        return ret;
    }

    if ((ret = set_src_nh(entry)) < 0){
        return ret;
    }

    return 0;
}


static int set_dst_vif(struct vr_n3k_offload_entry* entry)
{
    entry->dst_vif = vr_dpdk_n3k_offload_interface_get(
        nh_interface_id(entry->dst_nh), &entry->dst_virtual_vif);
    if (!entry->dst_vif) {
        RTE_LOG(ERR, VROUTER, "vr_dpdk_n3k_fill_offload_entry: "
            "dst_vif == NULL for dst_nh->id == %d.\n", entry->dst_nh->nh_id);
        return -ENOENT;
    }
    return 0;
}

static int set_src_vif(struct vr_n3k_offload_entry* entry)
{
    entry->src_vif = vr_dpdk_n3k_offload_interface_get(
        nh_interface_id(entry->src_nh), &entry->src_virtual_vif);
    if (!entry->src_vif) {
        RTE_LOG(ERR, VROUTER, "vr_dpdk_n3k_fill_offload_entry: "
            "src_vif == NULL for src_nh->id == %d.\n", entry->src_nh->nh_id);
        return -ENOENT;
    }
    return 0;
}

// Returns 0 when execution is successful.
static int
set_vifs(struct vr_n3k_offload_entry* entry)
{
    int ret;
    if ((ret = set_dst_vif(entry)) < 0) {
        return ret;
    }

    if ((ret = set_src_vif(entry)) < 0){
        return ret;
    }

    return 0;
}

static int
vr_dpdk_n3k_offload_fill_vxlan_label(struct vr_n3k_offload_entry *entry,
                   const struct vr_n3k_offload_bridge_value *bridge_value)
{
    const struct vr_nexthop* nh =
      vr_dpdk_n3k_offload_nexthop_get(bridge_value->nh_id);

    if (!nh) {
        RTE_LOG(ERR, VROUTER,
            "%s(): vr_dpdk_n3k_offload_nexthop_get failed for nh_id=%d\n",
            __FUNCTION__, bridge_value->nh_id);
        return -EINVAL;
    }

    entry->tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN;

    if (nh->nh_type == NH_COMPOSITE)
        return fill_label_in_entry_from_composite_nh(entry, nh);

    entry->tunnel_label = bridge_value->label;
    return 0;
}

// Returns 0 when execution is successful.
static int
set_vxlan(struct vr_n3k_offload_entry* entry)
{
    if (entry->dst_nh->nh_type == NH_TUNNEL && (entry->dst_nh->nh_flags & NH_FLAG_TUNNEL_VXLAN)) {
        struct vr_n3k_offload_bridge_value bridge_value;
        int ret = find_bridge_value_for_dst_overlay_mac_in_bridge_table(
            entry, &bridge_value);
        if (ret < 0) return -ENOENT;
        return vr_dpdk_n3k_offload_fill_vxlan_label(entry, &bridge_value);
    }
    else if (entry->src_nh->nh_type == NH_TUNNEL &&
            (entry->src_nh->nh_flags & NH_FLAG_TUNNEL_VXLAN)) {
        struct vr_n3k_offload_bridge_value bridge_value;
        int ret = find_bridge_value_for_src_overlay_mac_in_bridge_table(
            entry, &bridge_value);
        if (ret < 0) return -ENOENT;

        const struct vr_nexthop * nh =
            vr_dpdk_n3k_offload_nexthop_get(bridge_value.nh_id);
        if (!nh) {
            RTE_LOG(ERR, VROUTER,
                "%s(): vr_dpdk_n3k_offload_nexthop_get failed for nh_id=%d\n",
                __FUNCTION__, bridge_value.nh_id);
            return -EINVAL;
        }

        entry->tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN;

        /* Label is already set during composite NH selection for ingress composite NHs */
        if (nh->nh_type == NH_COMPOSITE)
            return 0;

        entry->tunnel_label = bridge_value.label;
    }
    return 0;
}

// Returns 0 when execution is successful.
static int
set_mpls(struct vr_n3k_offload_entry* entry)
{
    bool is_mpls_tunnel = entry->dst_nh->nh_type == NH_TUNNEL &&
        ((entry->dst_nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS) ||
         (entry->dst_nh->nh_flags & NH_FLAG_TUNNEL_GRE));
    bool is_l3 = entry->route_traffic == true;
    bool is_l2 = entry->route_traffic == false;

    if (is_mpls_tunnel && is_l2) {
        return vr_dpdk_n3k_offload_entry_fill_mpls_l2(entry);
    }
    else if (is_mpls_tunnel && is_l3) {
        return vr_dpdk_n3k_offload_entry_fill_mpls_l3(entry);
    }

    if (entry->src_nh->nh_type == NH_TUNNEL &&
       (entry->src_nh->nh_flags & NH_FLAG_TUNNEL_UDP_MPLS ||
        entry->src_nh->nh_flags & NH_FLAG_TUNNEL_GRE)) {
        struct vr_n3k_offload_mpls mpls;
        if (vr_dpdk_n3k_offload_mpls_get_by_nh(entry->dst_nh->nh_id, &mpls) != 0) {
            RTE_LOG(ERR, VROUTER,
            "%s(): mpls = NULL for dst_nh->id == %d.\n",
            __FUNCTION__, entry->dst_nh->nh_id);
            return -ENOENT;
        }

        entry->tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP;
        entry->tunnel_label = mpls.label;
    }

    return 0;
}

static const struct vr_interface*
get_vif_for_mirror_id(uint8_t mirror_id, uint32_t flow_id)
{
    const struct vr_mirror_entry * mirror = vrouter_get_mirror(0, mirror_id);

    if (mirror == NULL) {
        RTE_LOG(ERR, VROUTER, "get_vif_for_mirror_id failed: "
            "mirror with id %d couldn't be found.\n",
            mirror_id);

        if (flow_id != VR_INVALID_HENTRY_INDEX) {
            vr_dpdk_n3k_offload_missing_mirrors_add_unlocked(
                mirror_id, flow_id);
        }
        return NULL;
    }

    if (mirror->mir_nh == NULL) {
        RTE_LOG(ERR, VROUTER, "get_vif_for_mirror_id failed: "
            "mirror with id %d points to NULL nh.\n",
            mirror_id);
        return NULL;
    }

    const struct vr_nexthop *nh = mirror->mir_nh;

    int nh_validate_ret = vr_dpdk_n3k_offload_nexthop_validate(nh);
    if (nh_validate_ret) {
        if (nh_validate_ret == -EAGAIN) {
            if (flow_id != VR_INVALID_HENTRY_INDEX) {
                vr_dpdk_n3k_offload_missing_mirror_nexthops_add_unlocked(
                        nh->nh_id, flow_id);
            }
        } else {
            RTE_LOG(ERR, VROUTER, "get_vif_for_mirror_id failed: "
                    "nexthop with id %d is not supported.\n", nh->nh_id);
        }
        return NULL;
    }

    const struct vr_interface * mirror_vif =
        vr_dpdk_n3k_offload_interface_get(nh_interface_id(nh), NULL);
    if (mirror_vif == NULL) {
        RTE_LOG(ERR, VROUTER, "get_vif_for_mirror_id failed: "
            "vif with id %d couldn't be found.\n",
            nh_interface_id(nh));

        if (flow_id != VR_INVALID_HENTRY_INDEX) {
            vr_dpdk_n3k_offload_missing_mirror_vifs_add_unlocked(
                nh_interface_id(nh), flow_id);
        }
        return NULL;
    }

    return mirror_vif;
}


// Returns 0 when execution is successful.
static int
set_mirror_per_flow(struct vr_n3k_offload_entry* entry)
{
    if (entry->flow->mirror_id == VR_MAX_MIRROR_INDICES) {
        entry->mirror_vif = NULL;
        return 0;
    }

    entry->mirror_vif = get_vif_for_mirror_id(entry->flow->mirror_id, VR_INVALID_HENTRY_INDEX);
    if (entry->mirror_vif == NULL) return -ENOENT;

    return 0;
}

// Returns 0 when execution is successful.
static int
set_mirror_per_interface(struct vr_n3k_offload_entry* entry)
{
    if (entry->dst_vif->vif_mirror_id == VR_MAX_MIRROR_INDICES
            && entry->src_vif->vif_mirror_id == VR_MAX_MIRROR_INDICES) {
        entry->mirror_vif = NULL;
        return 0;
    }

    uint8_t mirror_id = entry->dst_vif->vif_mirror_id;
    if (mirror_id == VR_MAX_MIRROR_INDICES) {
        mirror_id = entry->src_vif->vif_mirror_id;
    }
    entry->mirror_vif = get_vif_for_mirror_id(mirror_id, entry->flow->id);
    if (entry->mirror_vif == NULL){
        return -ENOENT;
    }

    return 0;
}

// Returns 0 when execution is successful.
static int
set_mirror(struct vr_n3k_offload_entry* entry)
{
    // This is arbitrary decision which mirroring has higher priority.
    // Only one mirroring vif is curently supported in offloading mechanism.
    // TODO: handle mirroring per flow and mirroring per interface when
    //       they both exist at once. That would require hardware changes.
    //
    int ret = set_mirror_per_flow(entry);
    if (ret != 0 || entry->mirror_vif != NULL)
        return ret;

    return set_mirror_per_interface(entry);
}

static void
vr_dpdk_n3k_offload_entry_print_flow_key(
    const struct vr_n3k_offload_flow* flow)
{
    char ip_addr[40];

    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: printing flow key for offload entry\n",
        __func__);
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->nh_id    = %u\n", __func__,
        flow->nh_id);

    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->src_ip   = %s\n", __func__,
        vr_dpdk_n3k_convert_ip_to_str(ip_addr, &flow->ip.src, flow->ip.type));
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->dst_ip   = %s\n", __func__,
        vr_dpdk_n3k_convert_ip_to_str(ip_addr, &flow->ip.dst, flow->ip.type));

    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->proto    = %u\n", __func__,
        flow->proto);
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->src_port = %u\n", __func__,
        rte_be_to_cpu_16(flow->src_port));
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->dst_port = %u\n", __func__,
        rte_be_to_cpu_16(flow->dst_port));
}

static int
vr_dpdk_n3k_call_offload_entry_actions(
    int (**actions)(struct vr_n3k_offload_entry *),
    struct vr_n3k_offload_entry *entry)
{
    int i = 0;
    while (1) {
        if (actions[i] == NULL) {
            return 0;
        } else {
            int ret = actions[i](entry);
            if (ret < 0) return ret;
        }
        ++i;
    }
    return 0;
}

int
vr_dpdk_n3k_fill_offload_entry(
    struct vr_n3k_offload_flow* flow,
    struct vr_n3k_offload_entry* entry)
{
    memset(entry, 0, sizeof(*entry));

    entry->flow = flow;

    vr_dpdk_n3k_offload_entry_print_flow_key(flow);

    typedef int (*fill_offload_entry_action)(struct vr_n3k_offload_entry*);

    fill_offload_entry_action actions[] = {
        set_reverse_flow_offload,
        set_packet_metadata,
        set_nh,
        set_vifs,
        set_vxlan,
        set_mpls,
        set_mirror,
        NULL
    };

    return vr_dpdk_n3k_call_offload_entry_actions(actions, entry);
}

int
vr_dpdk_n3k_fill_offload_entry_vifs(
    struct vr_n3k_offload_entry* entry)
{
    typedef int (*fill_offload_entry_action)(struct vr_n3k_offload_entry*);

    fill_offload_entry_action actions[] = {
        set_vifs,
        NULL
    };

    return vr_dpdk_n3k_call_offload_entry_actions(actions, entry);
}

int
vr_dpdk_n3k_fill_offload_entry_partial_start(
    struct vr_n3k_offload_flow* flow,
    struct vr_n3k_offload_entry* entry)
{
    memset(entry, 0, sizeof(*entry));

    entry->flow = flow;

    vr_dpdk_n3k_offload_entry_print_flow_key(flow);

    typedef int (*fill_offload_entry_action)(struct vr_n3k_offload_entry*);

    fill_offload_entry_action actions[] = {
        set_packet_metadata,
        set_nh,
        NULL
    };

    return vr_dpdk_n3k_call_offload_entry_actions(actions, entry);
}

int
vr_dpdk_n3k_fill_offload_entry_partial_end(
    struct vr_n3k_offload_flow* flow,
    struct vr_n3k_offload_entry* entry)
{
    typedef int (*fill_offload_entry_action)(struct vr_n3k_offload_entry*);

    fill_offload_entry_action actions[] = {
        set_reverse_flow_offload,
        set_vxlan,
        set_mpls,
        set_mirror,
        NULL
    };

    return vr_dpdk_n3k_call_offload_entry_actions(actions, entry);
}

int
vr_dpdk_n3k_fill_offload_entry_for_metadata(
    struct vr_n3k_offload_flow* flow,
    struct vr_n3k_offload_entry* entry)
{
    memset(entry, 0, sizeof(*entry));

    entry->flow = flow;

    if (entry->flow->ecmp_nh_idx == -1)
        entry->flow->ecmp_nh_idx = 0;

    vr_dpdk_n3k_offload_entry_print_flow_key(flow);

    typedef int (*fill_offload_entry_action)(struct vr_n3k_offload_entry*);

    fill_offload_entry_action actions[] = {
        set_packet_metadata,
        set_dst_nh,
        set_dst_vif,
        NULL
    };

    return vr_dpdk_n3k_call_offload_entry_actions(actions, entry);
}
