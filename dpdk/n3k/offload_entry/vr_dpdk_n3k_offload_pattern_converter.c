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
#include "../vr_dpdk_n3k_nexthop.h"
#include "../vr_dpdk_n3k_packet_metadata.h"

#include <vr_packet.h>
#include <vr_nexthop.h>
#include <vr_vxlan.h>

static struct rte_flow_item_port_id port_id_spec;
static struct rte_flow_item_port_id port_id_mask = {
    .id = -1,
};

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

static struct rte_flow_item_mpls mpls_spec;
static struct rte_flow_item_mpls mpls_mask = {
    .label_tc_s = "\xf\xff\xff",
    .ttl = -1
};

static struct rte_flow_item_eth eth_spec;
static struct rte_flow_item_eth eth_mask = {
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

static struct rte_flow_item_ipv4 ipv4_spec;
static struct rte_flow_item_ipv4 ipv4_mask = {
    .hdr = {
        .src_addr = -1,
        .dst_addr = -1,
        .next_proto_id = -1,
    },
};

static struct rte_flow_item_udp udp_spec;
static struct rte_flow_item_udp udp_mask = {
    .hdr = {
        .src_port = -1,
        .dst_port = -1,
    },
};

static struct rte_flow_item_tcp tcp_spec;
static struct rte_flow_item_tcp tcp_mask = {
    .hdr = {
        .src_port = -1,
        .dst_port = -1,
        .tcp_flags = 0xff
    },
};

static struct rte_flow_item pattern[] = {
    [PATTERN_PORT_ID] = {
        .type = RTE_FLOW_ITEM_TYPE_PORT_ID,
        .spec = &port_id_spec,
        .mask = &port_id_mask,
        .last = NULL,
    },
    [PATTERN_OUTER_ETH] = {
        .type = RTE_FLOW_ITEM_TYPE_ETH,
        .spec = &outer_eth_spec,
        .mask = &outer_eth_mask,
        .last = NULL,
    },
    [PATTERN_OUTER_IPV4] = {
        .type = RTE_FLOW_ITEM_TYPE_IPV4,
        .spec = &outer_ipv4_spec,
        .mask = &outer_ipv4_mask,
        .last = NULL,
    },
    [PATTERN_OUTER_UDP] = {
        .type = RTE_FLOW_ITEM_TYPE_UDP,
        .spec = &outer_udp_spec,
        .mask = &outer_udp_mask,
        .last = NULL,
    },
    [PATTERN_VXLAN] = {
        .type = RTE_FLOW_ITEM_TYPE_VXLAN,
        .spec = &vxlan_spec,
        .mask = &vxlan_mask,
        .last = NULL,
    },
    [PATTERN_MPLS] = {
        .type = RTE_FLOW_ITEM_TYPE_MPLS,
        .spec = &mpls_spec,
        .mask = &mpls_mask,
        .last = NULL,
    },
    [PATTERN_ETH] = {
        .type = RTE_FLOW_ITEM_TYPE_ETH,
        .spec = &eth_spec,
        .mask = &eth_mask,
        .last = NULL,
    },
    [PATTERN_IPV4] = {
        .type = RTE_FLOW_ITEM_TYPE_IPV4,
        .spec = &ipv4_spec,
        .mask = &ipv4_mask,
        .last = NULL,
    },
    [PATTERN_UDP] = {
        .type = RTE_FLOW_ITEM_TYPE_UDP,
        .spec = &udp_spec,
        .mask = &udp_mask,
        .last = NULL,
    },
    [PATTERN_TCP] = {
        .type = RTE_FLOW_ITEM_TYPE_TCP,
        .spec = &tcp_spec,
        .mask = &tcp_mask,
        .last = NULL,
    },
    [PATTERN_END] = {
        .type = RTE_FLOW_ITEM_TYPE_END,
        .spec = NULL,
        .mask = NULL,
        .last = NULL,
    },
};

static void
reset_pattern(void)
{
    int i;

    for (i = 0; i < PATTERN_END; ++i) {
        pattern[i].type = RTE_FLOW_ITEM_TYPE_VOID;
    }
}

static void
set_pattern_port_id(uint32_t id)
{
    pattern[PATTERN_PORT_ID].type = RTE_FLOW_ITEM_TYPE_PORT_ID;
    port_id_spec.id = id;
}

static void
set_pattern_outer_eth(const uint8_t *smac, const uint8_t *dmac)
{
    pattern[PATTERN_OUTER_ETH].type = RTE_FLOW_ITEM_TYPE_ETH;
    outer_eth_spec.type = RTE_BE16(VR_ETH_PROTO_IP);
    memcpy(outer_eth_spec.src.addr_bytes, smac, VR_ETHER_ALEN);
    memcpy(outer_eth_spec.dst.addr_bytes, dmac, VR_ETHER_ALEN);
}

static void
set_pattern_outer_ipv4(rte_be32_t src, rte_be32_t dst, uint8_t proto)
{
    pattern[PATTERN_OUTER_IPV4].type = RTE_FLOW_ITEM_TYPE_IPV4;
    outer_ipv4_spec.hdr.src_addr = src;
    outer_ipv4_spec.hdr.dst_addr = dst;
    outer_ipv4_spec.hdr.next_proto_id = proto;
}

static void
set_pattern_outer_udp(rte_be16_t src, rte_be16_t dst)
{
    pattern[PATTERN_OUTER_UDP].type = RTE_FLOW_ITEM_TYPE_UDP;
    outer_udp_spec.hdr.src_port = src;
    outer_udp_spec.hdr.dst_port = dst;
}

static void
set_pattern_vxlan(uint32_t vnid)
{
    pattern[PATTERN_VXLAN].type = RTE_FLOW_ITEM_TYPE_VXLAN;
    const uint32_t vni = RTE_BE32(vnid << VR_VXLAN_VNID_SHIFT);
    memcpy(vxlan_spec.vni, &vni, 3);
}

static void
set_pattern_mpls(rte_le32_t label)
{
    pattern[PATTERN_MPLS].type = RTE_FLOW_ITEM_TYPE_MPLS;
    const rte_be32_t mplabel = RTE_BE32((label & VR_MPLS_LABEL_MASK) << VR_MPLS_LABEL_SHIFT);
    memcpy(mpls_spec.label_tc_s, &mplabel, 3);
    //mpls_spec.ttl = ttl;
}

static void
set_pattern_inner_eth(const uint8_t *smac, const uint8_t *dmac)
{
    pattern[PATTERN_ETH].type = RTE_FLOW_ITEM_TYPE_ETH;
    eth_spec.type = RTE_BE16(VR_ETH_PROTO_IP);
    memcpy(eth_spec.src.addr_bytes, smac, VR_ETHER_ALEN);
    memcpy(eth_spec.dst.addr_bytes, dmac, VR_ETHER_ALEN);
}

static void
set_pattern_inner_ipv4(rte_be32_t src, rte_be32_t dst, uint8_t proto)
{
    pattern[PATTERN_IPV4].type = RTE_FLOW_ITEM_TYPE_IPV4;
    ipv4_spec.hdr.src_addr = src;
    ipv4_spec.hdr.dst_addr = dst;
    ipv4_spec.hdr.next_proto_id = proto;
}

static void
set_pattern_inner_udp(rte_be16_t src, rte_be16_t dst)
{
    pattern[PATTERN_UDP].type = RTE_FLOW_ITEM_TYPE_UDP;
    udp_spec.hdr.src_port = src;
    udp_spec.hdr.dst_port = dst;
}

static void
set_pattern_inner_tcp(rte_be16_t src, rte_be16_t dst)
{
    pattern[PATTERN_TCP].type = RTE_FLOW_ITEM_TYPE_TCP;
    tcp_spec.hdr.src_port = src;
    tcp_spec.hdr.dst_port = dst;

    // TODO
    // PMD for N3k is dependent on value of tcp_flags.
    // This value is part of a key for the flow (as of 2020-07).
    // It should be clarified how value of tcp_flags affects
    // packet matching.
    // tcp_flags was set implicitly to 0 so far (pattern is a
    // static variable). This explicit assignment is a memento to
    // figure it out.
    tcp_spec.hdr.tcp_flags = 0;
}

static int
set_pattern_inner_transport(const struct vr_n3k_offload_flow *flow)
{
    switch (flow->proto) {
        case VR_IP_PROTO_TCP:
            set_pattern_inner_tcp(flow->src_port, flow->dst_port);
            return 0;

        case VR_IP_PROTO_UDP:
            set_pattern_inner_udp(flow->src_port, flow->dst_port);
            return 0;

        default:
            return -1;
    }
}

static void
set_pattern_outer_headers(
    const struct vr_n3k_offload_entry *entry)
{
    set_pattern_outer_eth(entry->src_nh->dst_mac, entry->src_nh->src_mac);
    set_pattern_outer_ipv4(
        entry->src_nh->tunnel_dst_ip,
        entry->src_nh->tunnel_src_ip,
        VR_IP_PROTO_UDP);

    switch (entry->tunnel_type) {
        case VR_N3K_OFFLOAD_TUNNEL_VXLAN:
            set_pattern_outer_udp(
                entry->flow->tunnel_udp_src_port,
                RTE_BE16(VR_VXLAN_UDP_DST_PORT));

            set_pattern_vxlan(entry->tunnel_label);
            break;

        case VR_N3K_OFFLOAD_TUNNEL_MPLS:
            set_pattern_outer_udp(
                entry->flow->tunnel_udp_src_port,
                RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT));

            set_pattern_mpls(entry->tunnel_label);
            break;

        default:
            break;
    }
    //TODO(smartnic) MPLSoGRE
}

int
vr_dpdk_n3k_offload_entry_to_rte_flow_pattern(
    struct vr_n3k_offload_entry *entry, struct rte_flow_item **out_pattern)
{
    int ret;

    reset_pattern();

    set_pattern_port_id(entry->src_vif->port_id);

    if (entry->src_nh->type == NH_TUNNEL) {
        set_pattern_outer_headers(entry);

        if (entry->dst_nh->nh_family != AF_INET) {
            set_pattern_inner_eth(
                entry->pkt_metadata.inner_src_mac,
                entry->pkt_metadata.inner_dst_mac);
        }
    } else {
        set_pattern_inner_eth(
            entry->pkt_metadata.inner_src_mac,
            entry->pkt_metadata.inner_dst_mac);
    }

    const struct vr_n3k_offload_flow *flow = entry->flow;
    set_pattern_inner_ipv4(flow->src_ip, flow->dst_ip, flow->proto);
    ret = set_pattern_inner_transport(flow);
    if (ret)
        return ret;

    *out_pattern = pattern;
    return 0;
}
