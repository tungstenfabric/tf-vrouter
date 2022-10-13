/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_offload_converter.h"
#include "vr_dpdk_n3k_offload_entry.h"
#include "vr_dpdk_n3k_rte_flow_defs.h"

#include "../vr_dpdk_n3k_flow.h"
#include "../vr_dpdk_n3k_interface.h"
#include "../vr_dpdk_n3k_mpls.h"
#include "../vr_dpdk_n3k_nexthop.h"
#include "../vr_dpdk_n3k_packet_metadata.h"
#include "../vr_dpdk_n3k_packet_parser.h"
#include "../vr_dpdk_n3k_vxlan.h"

#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_mpls.h>
#include <rte_udp.h>
#include <vr_dpdk.h>
#include <vr_nexthop.h>
#include <vr_packet.h>
#include <vr_vxlan.h>

enum { MAX_FLOW_ACTIONS = 20 };

#define PUSH_ACTION(action_ptr, action_type, action_conf) \
    do {                                                  \
        (*(action_ptr))->type = (action_type);            \
        (*(action_ptr))->conf = (action_conf);            \
        (*action_ptr)++;                                  \
    } while (false)

enum {
    N3K_OFFLOAD_ENCAP_TOS = 0,
    N3K_OFFLOAD_ENCAP_TTL = 64,
};

static const uint8_t VROUTER_MAC[] = {0x00, 0x00, 0x5e, 0x00, 0x01, 0x00};

static struct rte_flow_item_eth outer_eth_spec = {
    .type = RTE_BE16(VR_ETH_PROTO_IP),
};

static struct rte_flow_item_eth outer_eth_mask = {
    .type = -1,
    .src = {
        .addr_bytes = {
            0xff, 0xff, 0xff,
            0xff, 0xff, 0xff,
        },
    },
    .dst = {
        .addr_bytes = {
            0xff, 0xff, 0xff,
            0xff, 0xff, 0xff,
        },
    },
};

static struct rte_flow_item_ipv4 outer_ipv4_spec;
static struct rte_flow_item_ipv4 outer_ipv4_mask = {
    .hdr = {
        .src_addr = -1,
        .dst_addr = -1,
        .next_proto_id = -1,
        .time_to_live = -1,
        .type_of_service = -1,
    },
};

static struct rte_flow_item_udp outer_udp_spec;
static struct rte_flow_item_udp outer_udp_mask = {
    .hdr = {
        .src_port = -1,
        .dst_port = -1,
    },
};

static struct rte_flow_item_vxlan vxlan_spec;
static struct rte_flow_item_vxlan vxlan_mask = {
    .vni = "\xff\xff\xff",
};

static struct rte_flow_item encap_pattern[] = {
    [ENCAP_ETH] = {
        .type = RTE_FLOW_ITEM_TYPE_ETH,
        .spec = &outer_eth_spec,
        .mask = &outer_eth_mask,
        .last = NULL,
    },
    [ENCAP_IPV4] = {
        .type = RTE_FLOW_ITEM_TYPE_IPV4,
        .spec = &outer_ipv4_spec,
        .mask = &outer_ipv4_mask,
        .last = NULL,
    },
    [ENCAP_UDP] = {
        .type = RTE_FLOW_ITEM_TYPE_UDP,
        .spec = &outer_udp_spec,
        .mask = &outer_udp_mask,
        .last = NULL,
    },
    [ENCAP_VXLAN] = {
        .type = RTE_FLOW_ITEM_TYPE_VXLAN,
        .spec = &vxlan_spec,
        .mask = &vxlan_mask,
        .last = NULL,
    },
    [ENCAP_END] = {
        .type = RTE_FLOW_ITEM_TYPE_END,
        .spec = NULL,
        .mask = NULL,
        .last = NULL,
    },
};

static struct rte_flow_action_of_set_vlan_vid vlan_set_id_action_conf = { 0 };
static struct rte_flow_action_of_set_vlan_pcp vlan_set_pcp_action_conf = { 0 };
static struct rte_flow_action_port_id port_id_action_conf = { 0 };

static struct rte_flow_action_set_mac set_smac_action_conf = {
    .mac_addr = {
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    },
};

static struct rte_flow_action_set_mac set_dmac_action_conf = {
    .mac_addr = {
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    },
};

static struct rte_flow_action_set_ipv4 set_ipv4_src_action_conf = {
    .ipv4_addr = 0,
};

static struct rte_flow_action_set_ipv4 set_ipv4_dst_action_conf = {
    .ipv4_addr = 0,
};

static struct rte_flow_action_vxlan_encap vxlan_encap_action_conf = {
    .definition = encap_pattern,
};

#define ENCAP_DECAP_BUFFER_SIZE 1024
static uint8_t raw_encap_buffer[ENCAP_DECAP_BUFFER_SIZE] = { 0 };

static struct rte_flow_action_raw_encap raw_encap_action_conf = {
    .data = raw_encap_buffer,
    .preserve = NULL,
    .size = 0,
};

static uint8_t raw_decap_buffer[ENCAP_DECAP_BUFFER_SIZE] = { 0 };

static struct rte_flow_action_raw_decap raw_decap_action_conf = {
    .data = raw_decap_buffer,
    .size = 0,
};

static struct rte_flow_action_mirror mirror_action_conf = {
    .port = 0,
    .mirror_modified = 0,
};

static struct rte_flow_action actions[MAX_FLOW_ACTIONS];

static void
push_action_vlan_pop(struct rte_flow_action **action)
{
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_OF_POP_VLAN, NULL);
}

static void
push_action_vlan_push(struct rte_flow_action **action)
{
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN, NULL);
}

static void
push_action_vlan_set_id(struct rte_flow_action **action, uint16_t id)
{
    vlan_set_id_action_conf.vlan_vid = RTE_BE16(id);

    PUSH_ACTION(
        action, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID, &vlan_set_id_action_conf);
}

static void
push_action_vlan_set_pcp(struct rte_flow_action **action, uint8_t pcp)
{
    vlan_set_pcp_action_conf.vlan_pcp = pcp;

    PUSH_ACTION(
        action, RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP, &vlan_set_pcp_action_conf);
}

static void
handle_vlan(struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    if ((entry->src_virtual_vif != NULL) && (entry->dst_virtual_vif == NULL))
        push_action_vlan_pop(action);

    else if ((entry->src_virtual_vif == NULL) && (entry->dst_virtual_vif != NULL)) {
        push_action_vlan_push(action);
        push_action_vlan_set_id(action, entry->dst_virtual_vif->vif_vlan_id);
        push_action_vlan_set_pcp(action, entry->pkt_metadata.tos);
    }

    else if ((entry->src_virtual_vif != NULL) && (entry->dst_virtual_vif != NULL)) {
        push_action_vlan_set_id(action, entry->dst_virtual_vif->vif_vlan_id);
        push_action_vlan_set_pcp(action, entry->pkt_metadata.tos);
    }
}

static void
push_action_port_id(struct rte_flow_action **action, uint32_t id)
{
    port_id_action_conf.id = id;
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_PORT_ID, &port_id_action_conf);
}

static void
push_action_vxlan_encap(struct rte_flow_action **action)
{
    PUSH_ACTION(
        action, RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP, &vxlan_encap_action_conf);
}

static void
push_action_vxlan_decap(struct rte_flow_action **action)
{
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_VXLAN_DECAP, NULL);
}

static void
push_action_raw_encap(struct rte_flow_action **action)
{
    if (raw_encap_action_conf.size != 0) {
        memset(raw_encap_buffer, 0, raw_encap_action_conf.size);
        raw_encap_action_conf.size = 0;
    }

    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_RAW_ENCAP, &raw_encap_action_conf);
}

static void
set_action_raw_encap_ether_hdr(
    struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac)
{
    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)
        (raw_encap_action_conf.data + raw_encap_action_conf.size);

    /*
      Must not happen - otherwise offload is broken.
      As the expression verified always returns the same value, RTE_ASSERT can be used
      as it is a noop if RTE_ENABLE_ASSERT is not specified
    */
    RTE_ASSERT((raw_encap_action_conf.size + sizeof(*hdr)) <= ENCAP_DECAP_BUFFER_SIZE);
    raw_encap_action_conf.size += sizeof(*hdr);

    hdr->d_addr = *dst_mac;
    hdr->s_addr = *src_mac;
    hdr->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
}

static void
set_action_raw_encap_ipv4_hdr(rte_be32_t src_ip, rte_be32_t dst_ip)
{
    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)
        (raw_encap_action_conf.data + raw_encap_action_conf.size);

    const uint8_t version_ihl = RTE_IPV4_VHL_DEF;
    const size_t  header_size =
        (version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    /*
      Must not happen - otherwise offload is broken.
      As the expression verified always returns the same value, RTE_ASSERT can be used
      as it is a noop if RTE_ENABLE_ASSERT is not specified
    */
    RTE_ASSERT((raw_encap_action_conf.size + header_size) <= ENCAP_DECAP_BUFFER_SIZE);
    raw_encap_action_conf.size += header_size;

    hdr->src_addr = src_ip;
    hdr->dst_addr = dst_ip;
    hdr->next_proto_id = IPPROTO_UDP;
    hdr->version_ihl = version_ihl;
    hdr->time_to_live = N3K_OFFLOAD_ENCAP_TTL;
}

static void
set_action_raw_encap_udp_hdr(rte_be16_t src_port, rte_be16_t dst_port)
{
    struct rte_udp_hdr *hdr = (struct rte_udp_hdr *)
        (raw_encap_action_conf.data + raw_encap_action_conf.size);

    /*
      Must not happen - otherwise offload is broken.
      As the expression verified always returns the same value, RTE_ASSERT can be used
      as it is a noop if RTE_ENABLE_ASSERT is not specified
    */
    RTE_ASSERT((raw_encap_action_conf.size + sizeof(*hdr)) <= ENCAP_DECAP_BUFFER_SIZE);
    raw_encap_action_conf.size += sizeof(*hdr);

    hdr->src_port = src_port;
    hdr->dst_port = dst_port;
}

static void
set_action_raw_encap_mpls_hdr(rte_le32_t label)
{
    struct rte_mpls_hdr *hdr = (struct rte_mpls_hdr *)
        (raw_encap_action_conf.data + raw_encap_action_conf.size);

    /*
      Must not happen - otherwise offload is broken.
      As the expression verified always returns the same value, RTE_ASSERT can be used
      as it is a noop if RTE_ENABLE_ASSERT is not specified
    */
    RTE_ASSERT((raw_encap_action_conf.size + sizeof(*hdr)) <= ENCAP_DECAP_BUFFER_SIZE);
    raw_encap_action_conf.size += sizeof(*hdr);

    hdr->tag_msb = RTE_BE16((label >> 4) & 0xffff);
    hdr->tag_lsb = label & 0xf;
}


static void
push_action_raw_decap(struct rte_flow_action **action)
{
    if (raw_decap_action_conf.size != 0) {
        memset(raw_decap_buffer, 0, raw_decap_action_conf.size);
        raw_decap_action_conf.size = 0;
    }

    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_RAW_DECAP, &raw_decap_action_conf);
}

static void
set_action_raw_decap_ether_hdr(
    struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac)
{
    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)
        (raw_decap_action_conf.data + raw_decap_action_conf.size);

    /*
      Must not happen - otherwise offload is broken.
      As the expression verified always returns the same value, RTE_ASSERT can be used
      as it is a noop if RTE_ENABLE_ASSERT is not specified
    */
    RTE_ASSERT((raw_decap_action_conf.size + sizeof(*hdr)) <= ENCAP_DECAP_BUFFER_SIZE);
    raw_decap_action_conf.size += sizeof(*hdr);

    hdr->d_addr = *dst_mac;
    hdr->s_addr = *src_mac;
    hdr->ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
}

static void
set_action_raw_decap_ipv4_hdr(rte_be32_t src_ip, rte_be32_t dst_ip)
{
    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)
        (raw_decap_action_conf.data + raw_decap_action_conf.size);

    const uint8_t version_ihl = RTE_IPV4_VHL_DEF;
    const size_t  header_size =
        (version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    /*
      Must not happen - otherwise offload is broken.
      As the expression verified always returns the same value, RTE_ASSERT can be used
      as it is a noop if RTE_ENABLE_ASSERT is not specified
    */
    RTE_ASSERT((raw_decap_action_conf.size + header_size) <= ENCAP_DECAP_BUFFER_SIZE);
    raw_decap_action_conf.size += header_size;

    hdr->src_addr = src_ip;
    hdr->dst_addr = dst_ip;
    hdr->next_proto_id = IPPROTO_UDP;
    hdr->version_ihl = version_ihl;
}

static void
set_action_raw_decap_udp_hdr(rte_be16_t src_port, rte_be16_t dst_port)
{
    struct rte_udp_hdr *hdr = (struct rte_udp_hdr *)
        (raw_decap_action_conf.data + raw_decap_action_conf.size);

    /*
      Must not happen - otherwise offload is broken.
      As the expression verified always returns the same value, RTE_ASSERT can be used
      as it is a noop if RTE_ENABLE_ASSERT is not specified
    */
    RTE_ASSERT((raw_decap_action_conf.size + sizeof(*hdr)) <= ENCAP_DECAP_BUFFER_SIZE);
    raw_decap_action_conf.size += sizeof(*hdr);

    hdr->src_port = src_port;
    hdr->dst_port = dst_port;
}

static void
set_action_raw_decap_mpls_hdr(rte_le32_t label)
{
    struct rte_mpls_hdr *hdr = (struct rte_mpls_hdr *)
        (raw_decap_action_conf.data + raw_decap_action_conf.size);

    /*
      Must not happen - otherwise offload is broken.
      As the expression verified always returns the same value, RTE_ASSERT can be used
      as it is a noop if RTE_ENABLE_ASSERT is not specified
    */
    RTE_ASSERT((raw_decap_action_conf.size + sizeof(*hdr)) <= ENCAP_DECAP_BUFFER_SIZE);
    raw_decap_action_conf.size += sizeof(*hdr);

    hdr->tag_msb = RTE_BE16((label >> 4) & 0xffff);
    hdr->tag_lsb = label & 0xf;
}

static void
push_action_set_src_mac(struct rte_flow_action **action, const uint8_t *mac)
{
    memcpy(set_smac_action_conf.mac_addr, mac, VR_ETHER_ALEN);
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_SET_MAC_SRC, &set_smac_action_conf);
}

static void
push_action_set_dst_mac(struct rte_flow_action **action, const uint8_t *mac)
{
    memcpy(set_dmac_action_conf.mac_addr, mac, VR_ETHER_ALEN);
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_SET_MAC_DST, &set_dmac_action_conf);
}

static void
push_action_dec_ttl(struct rte_flow_action **action)
{
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_DEC_TTL, NULL);
}

static void
push_action_set_src_ipv4(struct rte_flow_action **action, rte_be32_t addr)
{
    set_ipv4_src_action_conf.ipv4_addr = addr;
    PUSH_ACTION(
        action, RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC, &set_ipv4_src_action_conf);
}

static void
push_action_set_dst_ipv4(struct rte_flow_action **action, rte_be32_t addr)
{
    set_ipv4_dst_action_conf.ipv4_addr = addr;
    PUSH_ACTION(
        action, RTE_FLOW_ACTION_TYPE_SET_IPV4_DST, &set_ipv4_dst_action_conf);
}

static void
push_action_drop(struct rte_flow_action **action)
{
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_DROP, NULL);
}

static void
push_action_route(
    struct rte_flow_action **action, const uint8_t *smac, const uint8_t *dmac)
{
    push_action_set_src_mac(action, smac);
    push_action_set_dst_mac(action, dmac);
    push_action_dec_ttl(action);
}

static void
push_action_nat(
    struct rte_flow_action **action, const struct vr_n3k_offload_entry *entry)
{
    if (entry->reverse_flow->ip.type == VR_N3K_IP_TYPE_IPV6)
        return;

    if (entry->flow->flags & VR_FLOW_FLAG_SNAT) {
        push_action_set_src_ipv4(action, entry->reverse_flow->ip.dst.ipv4);
    }

    if (entry->flow->flags & VR_FLOW_FLAG_DNAT) {
        push_action_set_dst_ipv4(action, entry->reverse_flow->ip.src.ipv4);
    }
}

static void
push_action_mirror(
    struct rte_flow_action **action, uint32_t port_id, bool modified)
{
    mirror_action_conf.port = port_id;
    mirror_action_conf.mirror_modified = modified;

    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_MIRROR, &mirror_action_conf);
}

static void
handle_nat(struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    if (entry->flow->action == VR_FLOW_ACTION_NAT) {
        push_action_nat(action, entry);
    }
}

static void
handle_egress_mpls_l3(
    struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    push_action_raw_decap(action);

    const struct vr_dpdk_n3k_packet_metadata* md = &entry->pkt_metadata;
    set_action_raw_decap_ether_hdr((struct rte_ether_addr *)md->inner_src_mac,
        (struct rte_ether_addr *)md->inner_dst_mac);

    push_action_dec_ttl(action);
}

static void
handle_ingress_mpls_l3(
    struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    push_action_raw_encap(action);
    set_action_raw_encap_ether_hdr(
        (struct rte_ether_addr*) VROUTER_MAC,
        (struct rte_ether_addr*) nh_dst_mac(entry->dst_nh, entry->flow->underlay_ecmp_index));
}

static void
handle_vxlan_encap(
    struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    push_action_vxlan_encap(action);

    memcpy(
        outer_eth_spec.src.addr_bytes, nh_src_mac(entry->dst_nh, entry->flow->underlay_ecmp_index), VR_ETHER_ALEN);

    memcpy(
        outer_eth_spec.dst.addr_bytes, nh_dst_mac(entry->dst_nh, entry->flow->underlay_ecmp_index), VR_ETHER_ALEN);

    outer_ipv4_spec.hdr.src_addr = nh_tunnel_src_ip(entry->dst_nh);
    outer_ipv4_spec.hdr.dst_addr = nh_tunnel_dst_ip(entry->dst_nh);
    outer_ipv4_spec.hdr.next_proto_id = VR_IP_PROTO_UDP;
    outer_ipv4_spec.hdr.time_to_live = N3K_OFFLOAD_ENCAP_TTL;
    outer_ipv4_spec.hdr.type_of_service = N3K_OFFLOAD_ENCAP_TOS;

    outer_udp_spec.hdr.src_port = entry->flow->tunnel_udp_src_port;
    outer_udp_spec.hdr.dst_port = RTE_BE16(VR_VXLAN_UDP_DST_PORT);

    const uint32_t vni = RTE_BE32(entry->tunnel_label << VR_VXLAN_VNID_SHIFT);
    memcpy(vxlan_spec.vni, &vni, 3);
}

static void
handle_mpls_encap(
    struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    if (entry->route_traffic)
        handle_egress_mpls_l3(action, entry);

    push_action_raw_encap(action);

    set_action_raw_encap_ether_hdr(
        (struct rte_ether_addr *)nh_src_mac(entry->dst_nh, entry->flow->underlay_ecmp_index),
        (struct rte_ether_addr *)nh_dst_mac(entry->dst_nh, entry->flow->underlay_ecmp_index));

    set_action_raw_encap_ipv4_hdr(
        nh_tunnel_src_ip(entry->dst_nh),
        nh_tunnel_dst_ip(entry->dst_nh));

    set_action_raw_encap_udp_hdr(
        entry->flow->tunnel_udp_src_port,
        RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT));

    set_action_raw_encap_mpls_hdr(entry->tunnel_label);
}

static int
handle_encap(
    struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    handle_vlan(action, entry);
    handle_nat(action, entry);

    switch (entry->tunnel_type) {
        case VR_N3K_OFFLOAD_TUNNEL_VXLAN:
            handle_vxlan_encap(action, entry);
            break;

        case VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP:
            handle_mpls_encap(action, entry);
            break;

        default:
            return -EINVAL;
    }

    return 0;
}

static void
push_action_mpls_over_udp_decap(
    struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    const rte_be16_t mplsoudp_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    push_action_raw_decap(action);
    set_action_raw_decap_ether_hdr(
        (struct rte_ether_addr *)nh_dst_mac(entry->src_nh, entry->flow->underlay_ecmp_index),
        (struct rte_ether_addr *)nh_src_mac(entry->src_nh, entry->flow->underlay_ecmp_index));
    set_action_raw_decap_ipv4_hdr(
        nh_tunnel_dst_ip(entry->src_nh),
        nh_tunnel_src_ip(entry->src_nh));
    set_action_raw_decap_udp_hdr(
        entry->flow->tunnel_udp_src_port, mplsoudp_dst_port);
    set_action_raw_decap_mpls_hdr(entry->tunnel_label);

    if (entry->dst_nh->nh_family == AF_INET)
        handle_ingress_mpls_l3(action, entry);
}

static int
handle_decap(
    struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    switch (entry->tunnel_type) {
        case VR_N3K_OFFLOAD_TUNNEL_VXLAN:
            push_action_vxlan_decap(action);
            break;

        case VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP:
            push_action_mpls_over_udp_decap(action, entry);
            break;

        default:
            return -EINVAL;
    }

    handle_vlan(action, entry);
    handle_nat(action, entry);

    return 0;
}

static void
handle_local(
    struct rte_flow_action **action, struct vr_n3k_offload_entry *entry)
{
    if (entry->route_traffic)
        push_action_route(
            action,
            nh_src_mac(entry->dst_nh, entry->flow->underlay_ecmp_index),
            nh_dst_mac(entry->dst_nh, entry->flow->underlay_ecmp_index));

    handle_vlan(action, entry);
    handle_nat(action, entry);
}

static void
push_action_end(struct rte_flow_action **action)
{
    PUSH_ACTION(action, RTE_FLOW_ACTION_TYPE_END, NULL);
}

int
vr_dpdk_n3k_offload_entry_to_rte_flow_action(
    struct vr_n3k_offload_entry *entry, struct rte_flow_action **out_actions)
{
    struct rte_flow_action *action_ptr = actions;

    if (entry->flow->action == VR_FLOW_ACTION_DROP) {
        push_action_drop(&action_ptr);
        goto act_end;
    }

    int ret = 0;
    if (entry->dst_nh->nh_type == NH_TUNNEL) {
        ret = handle_encap(&action_ptr, entry);
    } else {
        if (entry->src_nh->nh_type == NH_TUNNEL) {
            ret = handle_decap(&action_ptr, entry);
        } else {
            handle_local(&action_ptr, entry);
        }
    }

    if (ret)
        return ret;

    push_action_port_id(&action_ptr, vif_port_id(entry->dst_vif));

    if (entry->mirror_vif) {
        const bool modified = entry->src_nh->nh_type == NH_TUNNEL;
        push_action_mirror(&action_ptr, vif_port_id(entry->mirror_vif), modified);
    }

act_end:
    push_action_end(&action_ptr);
    *out_actions = actions;
    return 0;
}
