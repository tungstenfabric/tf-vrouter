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

static struct rte_flow_action actions[] = {
    [ACTION_IPV4_SRC] = {
        .type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC,
        .conf = &set_ipv4_src_action_conf,
    },
    [ACTION_VXLAN_ENCAP] = {
        .type = RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP,
        .conf = &vxlan_encap_action_conf,
    },
    [ACTION_VXLAN_DECAP] = {
        .type = RTE_FLOW_ACTION_TYPE_VXLAN_DECAP,
        .conf = NULL,
    },
    [ACTION_RAW_ENCAP] = {
        .type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        .conf = &raw_encap_action_conf,
    },
    [ACTION_RAW_DECAP] = {
        .type = RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        .conf = &raw_decap_action_conf,
    },
    [ACTION_IPV4_DST] = {
        .type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST,
        .conf = &set_ipv4_dst_action_conf,
    },
    [ACTION_SET_SMAC] = {
        .type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC,
        .conf = &set_smac_action_conf,
    },
    [ACTION_SET_DMAC] = {
        .type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST,
        .conf = &set_dmac_action_conf,
    },
    [ACTION_DEC_TTL] = {
        .type = RTE_FLOW_ACTION_TYPE_DEC_TTL,
        .conf = NULL,
    },
    [ACTION_PORT_ID] = {
        .type = RTE_FLOW_ACTION_TYPE_PORT_ID,
        .conf = &port_id_action_conf,
    },
    [ACTION_DROP] = {
        .type = RTE_FLOW_ACTION_TYPE_DROP,
        .conf = NULL,
    },
    [ACTION_MIRROR] = {
        .type = RTE_FLOW_ACTION_TYPE_MIRROR,
        .conf = &mirror_action_conf,
    },
    [ACTION_END] = {
        .type = RTE_FLOW_ACTION_TYPE_END,
        .conf = NULL,
    },
};

static void
reset_actions(void)
{
    int i;

    for (i = 0; i < ACTION_END; ++i) {
        actions[i].type = RTE_FLOW_ACTION_TYPE_VOID;
    }
}

static void
set_action_port_id(uint32_t id)
{
    actions[ACTION_PORT_ID].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
    port_id_action_conf.id = id;
}

static void
set_action_vxlan_encap()
{
    actions[ACTION_VXLAN_ENCAP].type = RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP;
}

static void
set_action_vxlan_decap()
{
    actions[ACTION_VXLAN_DECAP].type = RTE_FLOW_ACTION_TYPE_VXLAN_DECAP;
}

static void
set_action_raw_encap()
{
    actions[ACTION_RAW_ENCAP].type = RTE_FLOW_ACTION_TYPE_RAW_ENCAP;
    if (raw_encap_action_conf.size != 0) {
        memset(raw_encap_buffer, 0, raw_encap_action_conf.size);
        raw_encap_action_conf.size = 0;
    }
}

static void
set_action_raw_encap_ether_hdr(
    struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac)
{
    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)(raw_encap_action_conf.data + raw_encap_action_conf.size);

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
    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)(raw_encap_action_conf.data + raw_encap_action_conf.size);

    const uint8_t version_ihl = RTE_IPV4_VHL_DEF;
    const size_t  header_size = (version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

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
    struct rte_udp_hdr *hdr = (struct rte_udp_hdr *)(raw_encap_action_conf.data + raw_encap_action_conf.size);

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
    struct rte_mpls_hdr *hdr = (struct rte_mpls_hdr *)(raw_encap_action_conf.data + raw_encap_action_conf.size);

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
set_action_raw_decap()
{
    actions[ACTION_RAW_DECAP].type = RTE_FLOW_ACTION_TYPE_RAW_DECAP;
    if (raw_decap_action_conf.size != 0) {
        memset(raw_decap_buffer, 0, raw_decap_action_conf.size);
        raw_decap_action_conf.size = 0;
    }
}

static void
set_action_raw_decap_ether_hdr(
    struct rte_ether_addr *src_mac, struct rte_ether_addr *dst_mac)
{
    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)(raw_decap_action_conf.data + raw_decap_action_conf.size);

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
    struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)(raw_decap_action_conf.data + raw_decap_action_conf.size);

    const uint8_t version_ihl = RTE_IPV4_VHL_DEF;
    const size_t  header_size = (version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

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
    struct rte_udp_hdr *hdr = (struct rte_udp_hdr *)(raw_decap_action_conf.data + raw_decap_action_conf.size);

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
    struct rte_mpls_hdr *hdr = (struct rte_mpls_hdr *)(raw_decap_action_conf.data + raw_decap_action_conf.size);

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
set_action_set_src_mac(const uint8_t *mac)
{
    actions[ACTION_SET_SMAC].type = RTE_FLOW_ACTION_TYPE_SET_MAC_SRC;
    memcpy(set_smac_action_conf.mac_addr, mac, VR_ETHER_ALEN);
}

static void
set_action_set_dst_mac(const uint8_t *mac)
{
    actions[ACTION_SET_DMAC].type = RTE_FLOW_ACTION_TYPE_SET_MAC_DST;
    memcpy(set_dmac_action_conf.mac_addr, mac, VR_ETHER_ALEN);
}

static void
set_action_dec_ttl()
{
    actions[ACTION_DEC_TTL].type = RTE_FLOW_ACTION_TYPE_DEC_TTL;
}

static void
set_action_set_src_ipv4(rte_be32_t addr)
{
    actions[ACTION_IPV4_SRC].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC;
    set_ipv4_src_action_conf.ipv4_addr = addr;
}

static void
set_action_set_dst_ipv4(rte_be32_t addr)
{
    actions[ACTION_IPV4_DST].type = RTE_FLOW_ACTION_TYPE_SET_IPV4_DST;
    set_ipv4_dst_action_conf.ipv4_addr = addr;
}

static bool
is_action_drop(void)
{
    if (actions[ACTION_DROP].type == RTE_FLOW_ACTION_TYPE_DROP) {
        return true;
    } else {
        return false;
    }
}

static void
set_action_drop(void)
{
    actions[ACTION_DROP].type = RTE_FLOW_ACTION_TYPE_DROP;
}

static void
set_action_route(const uint8_t *smac, const uint8_t *dmac)
{
    set_action_set_src_mac(smac);
    set_action_set_dst_mac(dmac);
    set_action_dec_ttl();
}

static void
set_action_nat(const struct vr_n3k_offload_entry *entry)
{
    if (entry->reverse_flow->ip.type == VR_N3K_IP_TYPE_IPV6)
        return;

    if (entry->flow->flags & VR_FLOW_FLAG_SNAT) {
        set_action_set_src_ipv4(entry->reverse_flow->ip.dst.ipv4);
    }

    if (entry->flow->flags & VR_FLOW_FLAG_DNAT) {
        set_action_set_dst_ipv4(entry->reverse_flow->ip.src.ipv4);
    }
}

static void
set_action_mirror(uint32_t port_id, bool modified)
{
    actions[ACTION_MIRROR].type = RTE_FLOW_ACTION_TYPE_MIRROR;
    mirror_action_conf.port = port_id;
    mirror_action_conf.mirror_modified = modified;
}

static void
handle_flow_action(const struct vr_n3k_offload_entry *entry)
{
    switch (entry->flow->action) {
        case VR_FLOW_ACTION_FORWARD:
            break;

        case VR_FLOW_ACTION_NAT:
            set_action_nat(entry);
            break;

        case VR_FLOW_ACTION_DROP:
            set_action_drop();
            break;

        default:
            break;
    }
}

static void
convert_encap(struct vr_n3k_offload_entry *entry)
{
    if (entry->tunnel_type == VR_N3K_OFFLOAD_TUNNEL_VXLAN) {
        set_action_vxlan_encap();

        memcpy(
            outer_eth_spec.src.addr_bytes, nh_src_mac(entry->dst_nh), VR_ETHER_ALEN);

        memcpy(
            outer_eth_spec.dst.addr_bytes, nh_dst_mac(entry->dst_nh), VR_ETHER_ALEN);

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
    if (entry->tunnel_type == VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP) {
        set_action_raw_encap();

        set_action_raw_encap_ether_hdr((struct rte_ether_addr *)nh_src_mac(entry->dst_nh),
            (struct rte_ether_addr *)nh_dst_mac(entry->dst_nh));

        set_action_raw_encap_ipv4_hdr(
            nh_tunnel_src_ip(entry->dst_nh),
            nh_tunnel_dst_ip(entry->dst_nh));

        set_action_raw_encap_udp_hdr(entry->flow->tunnel_udp_src_port,
            RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT));

        set_action_raw_encap_mpls_hdr(entry->tunnel_label);
    }
}

static void
handle_egress_mpls_l3(struct vr_n3k_offload_entry *entry)
{
    set_action_raw_decap();

    const struct vr_dpdk_n3k_packet_metadata* md = &entry->pkt_metadata;
    set_action_raw_decap_ether_hdr((struct rte_ether_addr *)md->inner_src_mac,
        (struct rte_ether_addr *)md->inner_dst_mac);

    set_action_dec_ttl();
}

static void
handle_ingress_mpls_l3(struct vr_n3k_offload_entry *entry)
{
    set_action_raw_encap();
    set_action_raw_encap_ether_hdr((struct rte_ether_addr*) VROUTER_MAC,
        (struct rte_ether_addr*) nh_dst_mac(entry->dst_nh));
}

static void
set_action_mpls_over_udp_decap(struct vr_n3k_offload_entry *entry)
{
    const rte_be16_t mplsoudp_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    set_action_raw_decap();
    set_action_raw_decap_ether_hdr(
        (struct rte_ether_addr *)nh_dst_mac(entry->src_nh),
        (struct rte_ether_addr *)nh_src_mac(entry->src_nh));
    set_action_raw_decap_ipv4_hdr(
        nh_tunnel_dst_ip(entry->src_nh),
        nh_tunnel_src_ip(entry->src_nh));
    set_action_raw_decap_udp_hdr(
        entry->flow->tunnel_udp_src_port, mplsoudp_dst_port);
    set_action_raw_decap_mpls_hdr(entry->tunnel_label);

    if (entry->dst_nh->nh_family == AF_INET)
        handle_ingress_mpls_l3(entry);
}

int
vr_dpdk_n3k_offload_entry_to_rte_flow_action(
    struct vr_n3k_offload_entry *entry, struct rte_flow_action **out_actions)
{
    reset_actions();

    handle_flow_action(entry);

    if (is_action_drop()) {
        *out_actions = actions;
        return 0;
    }

    if (entry->dst_nh->nh_type == NH_TUNNEL) {
        if (entry->route_traffic)
            handle_egress_mpls_l3(entry);
        convert_encap(entry);
    } else {
        if (entry->src_nh->nh_type == NH_TUNNEL) {
            switch (entry->tunnel_type) {
                case VR_N3K_OFFLOAD_TUNNEL_VXLAN:
                    set_action_vxlan_decap();
                    break;

                case VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP:
                    set_action_mpls_over_udp_decap(entry);
                    break;

                default:
                    return -EINVAL;
            }
        } else {
            if (entry->route_traffic)
                set_action_route(nh_src_mac(entry->dst_nh), nh_dst_mac(entry->dst_nh));
        }
    }

    set_action_port_id(vif_port_id(entry->dst_vif));

    if (entry->mirror_vif) {
        const bool modified = entry->src_nh->nh_type == NH_TUNNEL;
        set_action_mirror(vif_port_id(entry->mirror_vif), modified);
    }

    *out_actions = actions;
    return 0;
}
