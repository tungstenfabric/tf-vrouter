/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <cmocka.h>

#include <rte_ether.h>
#include <rte_flow.h>
#include <rte_ip.h>
#include <rte_mpls.h>
#include <rte_udp.h>

#include <offload_entry/vr_dpdk_n3k_offload_entry.h>
#include <offload_entry/vr_dpdk_n3k_offload_converter.h>
#include <offload_entry/vr_dpdk_n3k_rte_flow_defs.h>

#include <vr_dpdk_n3k_flow.h>
#include <vr_dpdk_n3k_interface.h>
#include <vr_dpdk_n3k_mpls.h>
#include <vr_dpdk_n3k_nexthop.h>
#include <vr_dpdk_n3k_packet_metadata.h>

#include <vr_packet.h>
#include <vr_nexthop.h>
#include <vr_vxlan.h>

#include "flow_test_utils.h"

static const uint8_t VROUTER_MAC[] = {0x00, 0x00, 0x5e, 0x00, 0x01, 0x00};

static void
test_mpls_o_udp_decap_tcp(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_phy = 3;
    const uint16_t dst_port_id = 5;

    struct vr_dpdk_ethdev src_phy_ethdev = {
        .ethdev_port_id = src_port_phy,
    };
    struct vr_interface src_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &src_phy_ethdev,
    };

    struct vr_dpdk_ethdev dst_vf_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_vf_ethdev,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    struct vr_eth src_nh_data = {
        .eth_smac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
        .eth_dmac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_dst_ip.value,
                    .tun_dip = outer_src_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(src_nh.nh.nh_data, &src_nh_data, sizeof(src_nh_data));

    struct vr_nexthop dst_nh = {
        .nh_type = NH_ENCAP,
    };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    const rte_le32_t mpls_label = RTE_LE32(0xabcde);

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV4,
            .src = {
                .ipv4 = src_ip.value
            },
            .dst = {
                .ipv4 = dst_ip.value
            },
        },
        .proto = VR_IP_PROTO_TCP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_phy,
        .src_nh = &src_nh.nh,
        .dst_vif = &dst_vf,
        .dst_nh = &dst_nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_MPLS,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_TCP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    /* WHEN vr_n3k_offload_entry is converted to rte_flow */
    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    /* THEN rte_flow matches specified traffic */
    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_mpls *mpls_spec =
        (struct rte_flow_item_mpls *)flow_package.pattern[PATTERN_MPLS].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv4 *ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_IPV4].spec;

    struct rte_flow_item_tcp *tcp_spec =
        (struct rte_flow_item_tcp *)flow_package.pattern[PATTERN_TCP].spec;

    assert_int_equal(port_id_spec->id, src_port_phy);

    assert_memory_equal(
        outer_eth_spec->src.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        outer_eth_spec->dst.addr_bytes, src_nh_data.eth_smac,VR_ETHER_ALEN);
    assert_int_equal(outer_eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(outer_ipv4_spec->hdr.src_addr, outer_src_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.dst_addr, outer_dst_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(outer_udp_spec->hdr.src_port, outer_src_port);
    assert_int_equal(outer_udp_spec->hdr.dst_port, outer_dst_port);

    const rte_be32_t mpls_label_conv = RTE_BE32((mpls_label & VR_MPLS_LABEL_MASK) << VR_MPLS_LABEL_SHIFT);
    assert_memory_equal(mpls_spec->label_tc_s, &mpls_label_conv, 3);

    assert_memory_equal(eth_spec->src.addr_bytes, src_mac, VR_ETHER_ALEN);
    assert_memory_equal(eth_spec->dst.addr_bytes, dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ipv4_spec->hdr.src_addr, src_ip.value);
    assert_int_equal(ipv4_spec->hdr.dst_addr, dst_ip.value);
    assert_int_equal(ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_TCP);

    assert_int_equal(tcp_spec->hdr.src_port, src_port);
    assert_int_equal(tcp_spec->hdr.dst_port, dst_port);

    struct rte_flow_action_raw_decap *decap_action_conf =
        (struct rte_flow_action_raw_decap *)flow_package.actions[ACTION_RAW_DECAP].conf;

    assert_non_null(decap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)decap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    rte_le32_t result_label_msb = rte_be_to_cpu_16(mpls_hdr->tag_msb);
    rte_le32_t result_label = mpls_hdr->tag_lsb | (result_label_msb << 4);
    assert_int_equal(result_label, mpls_label);

    const size_t expected_decap_size =
        sizeof(struct rte_ether_hdr) +
        ip_hdr_size +
        sizeof(struct rte_udp_hdr) +
        sizeof(struct rte_mpls_hdr);
    assert_int_equal(decap_action_conf->size, expected_decap_size);

    assert_memory_equal(
        ether_hdr->s_addr.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        ether_hdr->d_addr.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    assert_int_equal(mpls_hdr->tag_msb, RTE_BE16((mpls_label >> 4) & 0xffff));
    assert_int_equal(mpls_hdr->tag_lsb, mpls_label & 0xf);

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)flow_package.actions[ACTION_PORT_ID].conf;

    assert_int_equal(port_id_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_decap_udp(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_phy = 3;
    const uint32_t dst_port_id = 5;

    struct vr_dpdk_ethdev src_phy_ethdev = {
        .ethdev_port_id = src_port_phy,
    };
    struct vr_interface src_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &src_phy_ethdev,
    };

    struct vr_dpdk_ethdev dst_vf_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_vf_ethdev,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    struct vr_eth src_nh_data = {
        .eth_smac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
        .eth_dmac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_dst_ip.value,
                    .tun_dip = outer_src_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(src_nh.nh.nh_data, &src_nh_data, sizeof(src_nh_data));

    struct vr_nexthop dst_nh = {
        .nh_type = NH_ENCAP,
    };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    const rte_le32_t mpls_label = RTE_LE32(0xabcde);

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV4,
            .src = {
                .ipv4 = src_ip.value
            },
            .dst = {
                .ipv4 = dst_ip.value
            },
        },
        .proto = VR_IP_PROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_phy,
        .src_nh = &src_nh.nh,
        .dst_vif = &dst_vf,
        .dst_nh = &dst_nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_MPLS,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    /* WHEN vr_n3k_offload_entry is converted to rte_flow */
    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    /* THEN rte_flow matches specified traffic */
    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_mpls *mpls_spec =
        (struct rte_flow_item_mpls *)flow_package.pattern[PATTERN_MPLS].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv4 *ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_IPV4].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    assert_int_equal(port_id_spec->id, src_port_phy);

    assert_memory_equal(
        outer_eth_spec->src.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        outer_eth_spec->dst.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(outer_eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(outer_ipv4_spec->hdr.src_addr, outer_src_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.dst_addr, outer_dst_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(outer_udp_spec->hdr.src_port, outer_src_port);
    assert_int_equal(outer_udp_spec->hdr.dst_port, outer_dst_port);

    const rte_be32_t mpls_label_conv = RTE_BE32((mpls_label & VR_MPLS_LABEL_MASK) << VR_MPLS_LABEL_SHIFT);
    assert_memory_equal(mpls_spec->label_tc_s, &mpls_label_conv, 3);

    assert_memory_equal(eth_spec->src.addr_bytes, src_mac, VR_ETHER_ALEN);
    assert_memory_equal(eth_spec->dst.addr_bytes, dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ipv4_spec->hdr.src_addr, src_ip.value);
    assert_int_equal(ipv4_spec->hdr.dst_addr, dst_ip.value);
    assert_int_equal(ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

    struct rte_flow_action_raw_decap *decap_action_conf =
        (struct rte_flow_action_raw_decap *)flow_package.actions[ACTION_RAW_DECAP].conf;

    assert_non_null(decap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)decap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    const size_t expected_decap_size =
        sizeof(struct rte_ether_hdr) +
        ip_hdr_size +
        sizeof(struct rte_udp_hdr) +
        sizeof(struct rte_mpls_hdr);
    assert_int_equal(decap_action_conf->size, expected_decap_size);

    assert_memory_equal(
        ether_hdr->s_addr.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        ether_hdr->d_addr.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    rte_le32_t result_label_msb = rte_be_to_cpu_16(mpls_hdr->tag_msb);
    rte_le32_t result_label = mpls_hdr->tag_lsb | (result_label_msb << 4);
    assert_int_equal(result_label, mpls_label);

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)flow_package.actions[ACTION_PORT_ID].conf;

    assert_non_null(decap_action_conf-> data);
    assert_int_equal(port_id_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_encap_tcp(void **state)
{
    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 3;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &dst_phy_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_ENCAP,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0xde, 0xad, 0xc0, 0xde, 0x00 },
        .eth_dmac = { 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00 },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_family = AF_INET,
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const rte_le32_t mpls_label = RTE_LE32(0xabcde);

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV4,
            .src = {
                .ipv4 = src_ip.value
            },
            .dst = {
                .ipv4 = dst_ip.value
            },
        },
        .proto = VR_IP_PROTO_TCP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_phy,
        .dst_nh = &dst_nh.nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_TCP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv4 *ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_IPV4].spec;

    struct rte_flow_item_tcp *tcp_spec =
        (struct rte_flow_item_tcp *)flow_package.pattern[PATTERN_TCP].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes, metadata.inner_src_mac, VR_ETHER_ALEN);
    assert_memory_equal(
        eth_spec->dst.addr_bytes, metadata.inner_dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ipv4_spec->hdr.src_addr, src_ip.value);
    assert_int_equal(ipv4_spec->hdr.dst_addr, dst_ip.value);
    assert_int_equal(ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_TCP);

    assert_int_equal(tcp_spec->hdr.src_port, src_port);
    assert_int_equal(tcp_spec->hdr.dst_port, dst_port);

    struct rte_flow_action_raw_encap *encap_action_conf =
        (struct rte_flow_action_raw_encap *)
            flow_package.actions[ACTION_RAW_ENCAP].conf;

    assert_non_null(encap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)encap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    assert_non_null(encap_action_conf->data);
    assert_null(encap_action_conf->preserve);
    assert_int_equal(encap_action_conf->size, sizeof(struct rte_ether_hdr) + ip_hdr_size + sizeof(struct rte_udp_hdr) + sizeof(struct rte_mpls_hdr));

    assert_memory_equal(ether_hdr->s_addr.addr_bytes, dst_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_memory_equal(ether_hdr->d_addr.addr_bytes, dst_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    rte_le32_t result_label_msb = rte_be_to_cpu_16(mpls_hdr->tag_msb);
    rte_le32_t result_label = mpls_hdr->tag_lsb | (result_label_msb << 4);
    assert_int_equal(result_label, mpls_label);

    struct rte_flow_action_port_id *port_action_conf =
        (struct rte_flow_action_port_id *)
            flow_package.actions[ACTION_PORT_ID].conf;

    assert_int_equal(port_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_encap_udp(void **state)
{
    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 3;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &dst_phy_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_ENCAP,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0xde, 0xad, 0xc0, 0xde, 0x00 },
        .eth_dmac = { 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00 },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_family = AF_INET,
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const rte_le32_t mpls_label = RTE_LE32(0xabcde);

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV4,
            .src = {
                .ipv4 = src_ip.value
            },
            .dst = {
                .ipv4 = dst_ip.value
            },
        },
        .proto = VR_IP_PROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_phy,
        .dst_nh = &dst_nh.nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv4 *ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_IPV4].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes, metadata.inner_src_mac, VR_ETHER_ALEN);
    assert_memory_equal(
        eth_spec->dst.addr_bytes, metadata.inner_dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ipv4_spec->hdr.src_addr, src_ip.value);
    assert_int_equal(ipv4_spec->hdr.dst_addr, dst_ip.value);
    assert_int_equal(ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

    struct rte_flow_action_raw_encap *encap_action_conf =
        (struct rte_flow_action_raw_encap *)
            flow_package.actions[ACTION_RAW_ENCAP].conf;

    assert_non_null(encap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)encap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    assert_non_null(encap_action_conf->data);
    assert_null(encap_action_conf->preserve);
    assert_int_equal(encap_action_conf->size, sizeof(struct rte_ether_hdr) + ip_hdr_size + sizeof(struct rte_udp_hdr) + sizeof(struct rte_mpls_hdr));

    assert_memory_equal(ether_hdr->s_addr.addr_bytes, dst_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_memory_equal(ether_hdr->d_addr.addr_bytes, dst_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    assert_int_equal(mpls_hdr->tag_msb, RTE_BE16((mpls_label >> 4) & 0xffff));
    assert_int_equal(mpls_hdr->tag_lsb, mpls_label & 0xf);

    struct rte_flow_action_port_id *port_action_conf =
        (struct rte_flow_action_port_id *)
            flow_package.actions[ACTION_PORT_ID].conf;

    assert_int_equal(port_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_encap_udp_l3(void **state)
{
    /**** GIVEN ****/

    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 3;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &dst_phy_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_L2_RCV,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    const uint16_t outer_src_port = RTE_BE16(60486);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0xde, 0xad, 0xc0, 0xde, 0x00 },
        .eth_dmac = { 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00 },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_family = AF_INET,
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const rte_le32_t mpls_label = RTE_LE32(31);

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV4,
            .src = {
                .ipv4 = src_ip.value
            },
            .dst = {
                .ipv4 = dst_ip.value
            },
        },
        .proto = VR_IP_PROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_phy,
        .dst_nh = &dst_nh.nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .route_traffic = true,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    /**** WHEN ****/

    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    /**** THEN ****/

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        RTE_FLOW_ACTION_TYPE_DEC_TTL,
        RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    // verify patterns

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv4 *ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_IPV4].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes, metadata.inner_src_mac, VR_ETHER_ALEN);
    assert_memory_equal(
        eth_spec->dst.addr_bytes, metadata.inner_dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ipv4_spec->hdr.src_addr, src_ip.value);
    assert_int_equal(ipv4_spec->hdr.dst_addr, dst_ip.value);
    assert_int_equal(ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

    // verify actions

    struct rte_flow_action_raw_decap *decap_action_conf =
        (struct rte_flow_action_raw_decap *)
            flow_package.actions[ACTION_RAW_DECAP].conf;

    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)(decap_action_conf->data);
    assert_memory_equal(
        hdr->s_addr.addr_bytes, src_mac, VR_ETHER_ALEN);
    assert_memory_equal(
        hdr->d_addr.addr_bytes, dst_mac, VR_ETHER_ALEN);
    assert_int_equal(hdr->ether_type, RTE_BE16(RTE_ETHER_TYPE_IPV4));

    struct rte_flow_action_raw_encap *encap_action_conf =
        (struct rte_flow_action_raw_encap *)
            flow_package.actions[ACTION_RAW_ENCAP].conf;

    assert_non_null(encap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)encap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    assert_non_null(encap_action_conf->data);
    assert_null(encap_action_conf->preserve);
    assert_int_equal(encap_action_conf->size, sizeof(struct rte_ether_hdr) + ip_hdr_size + sizeof(struct rte_udp_hdr) + sizeof(struct rte_mpls_hdr));

    assert_memory_equal(ether_hdr->s_addr.addr_bytes, dst_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_memory_equal(ether_hdr->d_addr.addr_bytes, dst_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT));

    assert_int_equal(mpls_hdr->tag_msb, RTE_BE16((mpls_label >> 4) & 0xffff));
    assert_int_equal(mpls_hdr->tag_lsb, mpls_label & 0xf);

    struct rte_flow_action_port_id *port_action_conf =
        (struct rte_flow_action_port_id *)
            flow_package.actions[ACTION_PORT_ID].conf;

    assert_int_equal(port_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_decap_udp_l3(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_phy = 3;
    const uint32_t dst_port_id = 5;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_phy,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_phy = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_phy_ethdev,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    struct vr_eth src_nh_data = {
        .eth_smac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
        .eth_dmac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_dst_ip.value,
                    .tun_dip = outer_src_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(src_nh.nh.nh_data, &src_nh_data, sizeof(src_nh_data));

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_ENCAP,
            .nh_family = AF_INET,
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    const rte_le32_t mpls_label = RTE_LE32(31);

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = false,
    };

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    memcpy(dst_nh.nh.nh_data, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV4,
            .src = {
                .ipv4 = src_ip.value
            },
            .dst = {
                .ipv4 = dst_ip.value
            },
        },
        .proto = VR_IP_PROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh.nh,
        .dst_vif = &dst_phy,
        .dst_nh = &dst_nh.nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_MPLS,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    /* WHEN vr_n3k_offload_entry is converted to rte_flow */
    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    /* THEN rte_flow matches specified traffic */
    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_mpls *mpls_spec =
        (struct rte_flow_item_mpls *)flow_package.pattern[PATTERN_MPLS].spec;

    struct rte_flow_item_ipv4 *ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_IPV4].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    assert_int_equal(port_id_spec->id, src_port_phy);

    assert_memory_equal(
        outer_eth_spec->src.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        outer_eth_spec->dst.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(outer_eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(outer_ipv4_spec->hdr.src_addr, outer_src_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.dst_addr, outer_dst_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(outer_udp_spec->hdr.src_port, outer_src_port);
    assert_int_equal(outer_udp_spec->hdr.dst_port, outer_dst_port);

    const rte_be32_t mpls_label_conv = RTE_BE32((mpls_label & VR_MPLS_LABEL_MASK) << VR_MPLS_LABEL_SHIFT);
    assert_memory_equal(mpls_spec->label_tc_s, &mpls_label_conv, 3);

    assert_int_equal(ipv4_spec->hdr.src_addr, src_ip.value);
    assert_int_equal(ipv4_spec->hdr.dst_addr, dst_ip.value);
    assert_int_equal(ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

    // verify actions

    struct rte_flow_action_raw_decap *decap_action_conf =
        (struct rte_flow_action_raw_decap *)flow_package.actions[ACTION_RAW_DECAP].conf;

    assert_non_null(decap_action_conf->data);

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(
        decap_action_conf->data + sizeof(struct rte_ether_hdr));
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    assert_int_equal(
        decap_action_conf->size,
        sizeof(struct rte_ether_hdr) +
            ip_hdr_size +
            sizeof(struct rte_udp_hdr) +
            sizeof(struct rte_mpls_hdr)
    );

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    rte_le32_t result_label_msb = rte_be_to_cpu_16(mpls_hdr->tag_msb);
    rte_le32_t result_label = mpls_hdr->tag_lsb | (result_label_msb << 4);
    assert_int_equal(result_label, mpls_label);

    struct rte_flow_action_raw_encap *encap_action_conf =
        (struct rte_flow_action_raw_encap *)flow_package.actions[ACTION_RAW_ENCAP].conf;

    assert_non_null(encap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)encap_action_conf->data;

    assert_memory_equal(ether_hdr->s_addr.addr_bytes, VROUTER_MAC, VR_ETHER_ALEN);
    assert_memory_equal(ether_hdr->d_addr.addr_bytes, dst_mac, VR_ETHER_ALEN);

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)flow_package.actions[ACTION_PORT_ID].conf;

    assert_non_null(decap_action_conf-> data);
    assert_int_equal(port_id_action_conf->id, dst_port_id);
}


static void
test_mpls_o_udp_decap_tcp_ipv6(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_phy = 3;
    const uint16_t dst_port_id = 5;

    struct vr_dpdk_ethdev src_phy_ethdev = {
        .ethdev_port_id = src_port_phy,
    };
    struct vr_interface src_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &src_phy_ethdev,
    };

    struct vr_dpdk_ethdev dst_vf_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_vf_ethdev,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    struct vr_eth src_nh_data = {
        .eth_smac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
        .eth_dmac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_dst_ip.value,
                    .tun_dip = outer_src_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(src_nh.nh.nh_data, &src_nh_data, sizeof(src_nh_data));

    struct vr_nexthop dst_nh = {
        .nh_type = NH_ENCAP,
    };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    const rte_le32_t mpls_label = RTE_LE32(0xabcde);

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV6
        },
        .proto = VR_IP_PROTO_TCP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    memcpy(flow.ip.src.ipv6, src_ip, VR_IP6_ADDRESS_LEN);
    memcpy(flow.ip.dst.ipv6, dst_ip, VR_IP6_ADDRESS_LEN);

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_phy,
        .src_nh = &src_nh.nh,
        .dst_vif = &dst_vf,
        .dst_nh = &dst_nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_MPLS,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV6,
        RTE_FLOW_ITEM_TYPE_TCP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    /* WHEN vr_n3k_offload_entry is converted to rte_flow */
    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    /* THEN rte_flow matches specified traffic */
    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_mpls *mpls_spec =
        (struct rte_flow_item_mpls *)flow_package.pattern[PATTERN_MPLS].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv6 *ipv6_spec =
        (struct rte_flow_item_ipv6 *)flow_package.pattern[PATTERN_IPV6].spec;

    struct rte_flow_item_tcp *tcp_spec =
        (struct rte_flow_item_tcp *)flow_package.pattern[PATTERN_TCP].spec;

    assert_int_equal(port_id_spec->id, src_port_phy);

    assert_memory_equal(
        outer_eth_spec->src.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        outer_eth_spec->dst.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(outer_eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(outer_ipv4_spec->hdr.src_addr, outer_src_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.dst_addr, outer_dst_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(outer_udp_spec->hdr.src_port, outer_src_port);
    assert_int_equal(outer_udp_spec->hdr.dst_port, outer_dst_port);

    const rte_be32_t mpls_label_conv = RTE_BE32((mpls_label & VR_MPLS_LABEL_MASK) << VR_MPLS_LABEL_SHIFT);
    assert_memory_equal(mpls_spec->label_tc_s, &mpls_label_conv, 3);

    assert_memory_equal(eth_spec->src.addr_bytes, src_mac, VR_ETHER_ALEN);
    assert_memory_equal(eth_spec->dst.addr_bytes, dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_memory_equal(ipv6_spec->hdr.src_addr, src_ip, VR_IP6_ADDRESS_LEN);
    assert_memory_equal(ipv6_spec->hdr.dst_addr, dst_ip, VR_IP6_ADDRESS_LEN);
    assert_int_equal(ipv6_spec->hdr.proto, VR_IP_PROTO_TCP);

    assert_int_equal(tcp_spec->hdr.src_port, src_port);
    assert_int_equal(tcp_spec->hdr.dst_port, dst_port);

    struct rte_flow_action_raw_decap *decap_action_conf =
        (struct rte_flow_action_raw_decap *)flow_package.actions[ACTION_RAW_DECAP].conf;

    assert_non_null(decap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)decap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    rte_le32_t result_label_msb = rte_be_to_cpu_16(mpls_hdr->tag_msb);
    rte_le32_t result_label = mpls_hdr->tag_lsb | (result_label_msb << 4);
    assert_int_equal(result_label, mpls_label);

    const size_t expected_decap_size =
        sizeof(struct rte_ether_hdr) +
        ip_hdr_size +
        sizeof(struct rte_udp_hdr) +
        sizeof(struct rte_mpls_hdr);
    assert_int_equal(decap_action_conf->size, expected_decap_size);

    assert_memory_equal(
        ether_hdr->s_addr.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        ether_hdr->d_addr.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    assert_int_equal(mpls_hdr->tag_msb, RTE_BE16((mpls_label >> 4) & 0xffff));
    assert_int_equal(mpls_hdr->tag_lsb, mpls_label & 0xf);

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)flow_package.actions[ACTION_PORT_ID].conf;

    assert_int_equal(port_id_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_decap_udp_ipv6(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_phy = 3;
    const uint32_t dst_port_id = 5;

    struct vr_dpdk_ethdev src_phy_ethdev = {
        .ethdev_port_id = src_port_phy,
    };
    struct vr_interface src_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &src_phy_ethdev,
    };

    struct vr_dpdk_ethdev dst_vf_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_vf_ethdev,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    struct vr_eth src_nh_data = {
        .eth_smac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
        .eth_dmac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_dst_ip.value,
                    .tun_dip = outer_src_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(src_nh.nh.nh_data, &src_nh_data, sizeof(src_nh_data));

    struct vr_nexthop dst_nh = {
        .nh_type = NH_ENCAP,
    };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    const rte_le32_t mpls_label = RTE_LE32(0xabcde);

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV6
        },
        .proto = VR_IP_PROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    memcpy(flow.ip.src.ipv6, src_ip, VR_IP6_ADDRESS_LEN);
    memcpy(flow.ip.dst.ipv6, dst_ip, VR_IP6_ADDRESS_LEN);

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_phy,
        .src_nh = &src_nh.nh,
        .dst_vif = &dst_vf,
        .dst_nh = &dst_nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_MPLS,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV6,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    /* WHEN vr_n3k_offload_entry is converted to rte_flow */
    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    /* THEN rte_flow matches specified traffic */
    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_mpls *mpls_spec =
        (struct rte_flow_item_mpls *)flow_package.pattern[PATTERN_MPLS].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv6 *ipv6_spec =
        (struct rte_flow_item_ipv6 *)flow_package.pattern[PATTERN_IPV6].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    assert_int_equal(port_id_spec->id, src_port_phy);

    assert_memory_equal(
        outer_eth_spec->src.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        outer_eth_spec->dst.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(outer_eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(outer_ipv4_spec->hdr.src_addr, outer_src_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.dst_addr, outer_dst_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(outer_udp_spec->hdr.src_port, outer_src_port);
    assert_int_equal(outer_udp_spec->hdr.dst_port, outer_dst_port);

    const rte_be32_t mpls_label_conv = RTE_BE32((mpls_label & VR_MPLS_LABEL_MASK) << VR_MPLS_LABEL_SHIFT);
    assert_memory_equal(mpls_spec->label_tc_s, &mpls_label_conv, 3);

    assert_memory_equal(eth_spec->src.addr_bytes, src_mac, VR_ETHER_ALEN);
    assert_memory_equal(eth_spec->dst.addr_bytes, dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_memory_equal(ipv6_spec->hdr.src_addr, src_ip, VR_IP6_ADDRESS_LEN);
    assert_memory_equal(ipv6_spec->hdr.dst_addr, dst_ip, VR_IP6_ADDRESS_LEN);
    assert_int_equal(ipv6_spec->hdr.proto, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

    struct rte_flow_action_raw_decap *decap_action_conf =
        (struct rte_flow_action_raw_decap *)flow_package.actions[ACTION_RAW_DECAP].conf;

    assert_non_null(decap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)decap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    const size_t expected_decap_size =
        sizeof(struct rte_ether_hdr) +
        ip_hdr_size +
        sizeof(struct rte_udp_hdr) +
        sizeof(struct rte_mpls_hdr);
    assert_int_equal(decap_action_conf->size, expected_decap_size);

    assert_memory_equal(
        ether_hdr->s_addr.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        ether_hdr->d_addr.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    rte_le32_t result_label_msb = rte_be_to_cpu_16(mpls_hdr->tag_msb);
    rte_le32_t result_label = mpls_hdr->tag_lsb | (result_label_msb << 4);
    assert_int_equal(result_label, mpls_label);

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)flow_package.actions[ACTION_PORT_ID].conf;

    assert_non_null(decap_action_conf-> data);
    assert_int_equal(port_id_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_encap_tcp_ipv6(void **state)
{
    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 3;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &dst_phy_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_ENCAP,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0xde, 0xad, 0xc0, 0xde, 0x00 },
        .eth_dmac = { 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00 },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_family = AF_INET,
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const rte_le32_t mpls_label = RTE_LE32(0xabcde);

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV6
        },
        .proto = VR_IP_PROTO_TCP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    memcpy(flow.ip.src.ipv6, src_ip, VR_IP6_ADDRESS_LEN);
    memcpy(flow.ip.dst.ipv6, dst_ip, VR_IP6_ADDRESS_LEN);

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_phy,
        .dst_nh = &dst_nh.nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV6,
        RTE_FLOW_ITEM_TYPE_TCP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv6 *ipv6_spec =
        (struct rte_flow_item_ipv6 *)flow_package.pattern[PATTERN_IPV6].spec;

    struct rte_flow_item_tcp *tcp_spec =
        (struct rte_flow_item_tcp *)flow_package.pattern[PATTERN_TCP].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes, metadata.inner_src_mac, VR_ETHER_ALEN);
    assert_memory_equal(
        eth_spec->dst.addr_bytes, metadata.inner_dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_memory_equal(ipv6_spec->hdr.src_addr, src_ip, VR_IP6_ADDRESS_LEN);
    assert_memory_equal(ipv6_spec->hdr.dst_addr, dst_ip, VR_IP6_ADDRESS_LEN);
    assert_int_equal(ipv6_spec->hdr.proto, VR_IP_PROTO_TCP);

    assert_int_equal(tcp_spec->hdr.src_port, src_port);
    assert_int_equal(tcp_spec->hdr.dst_port, dst_port);

    struct rte_flow_action_raw_encap *encap_action_conf =
        (struct rte_flow_action_raw_encap *)
            flow_package.actions[ACTION_RAW_ENCAP].conf;

    assert_non_null(encap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)encap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    assert_non_null(encap_action_conf->data);
    assert_null(encap_action_conf->preserve);
    assert_int_equal(encap_action_conf->size, sizeof(struct rte_ether_hdr) + ip_hdr_size + sizeof(struct rte_udp_hdr) + sizeof(struct rte_mpls_hdr));

    assert_memory_equal(ether_hdr->s_addr.addr_bytes, dst_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_memory_equal(ether_hdr->d_addr.addr_bytes, dst_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    rte_le32_t result_label_msb = rte_be_to_cpu_16(mpls_hdr->tag_msb);
    rte_le32_t result_label = mpls_hdr->tag_lsb | (result_label_msb << 4);
    assert_int_equal(result_label, mpls_label);

    struct rte_flow_action_port_id *port_action_conf =
        (struct rte_flow_action_port_id *)
            flow_package.actions[ACTION_PORT_ID].conf;

    assert_int_equal(port_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_encap_udp_ipv6(void **state)
{
    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 3;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &dst_phy_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_ENCAP,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0xde, 0xad, 0xc0, 0xde, 0x00 },
        .eth_dmac = { 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00 },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_family = AF_INET,
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const rte_le32_t mpls_label = RTE_LE32(0xabcde);

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV6
        },
        .proto = VR_IP_PROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    memcpy(flow.ip.src.ipv6, src_ip, VR_IP6_ADDRESS_LEN);
    memcpy(flow.ip.dst.ipv6, dst_ip, VR_IP6_ADDRESS_LEN);

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_phy,
        .dst_nh = &dst_nh.nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV6,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv6 *ipv6_spec =
        (struct rte_flow_item_ipv6 *)flow_package.pattern[PATTERN_IPV6].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes, metadata.inner_src_mac, VR_ETHER_ALEN);
    assert_memory_equal(
        eth_spec->dst.addr_bytes, metadata.inner_dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_memory_equal(ipv6_spec->hdr.src_addr, src_ip, VR_IP6_ADDRESS_LEN);
    assert_memory_equal(ipv6_spec->hdr.dst_addr, dst_ip, VR_IP6_ADDRESS_LEN);
    assert_int_equal(ipv6_spec->hdr.proto, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

    struct rte_flow_action_raw_encap *encap_action_conf =
        (struct rte_flow_action_raw_encap *)
            flow_package.actions[ACTION_RAW_ENCAP].conf;

    assert_non_null(encap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)encap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    assert_non_null(encap_action_conf->data);
    assert_null(encap_action_conf->preserve);
    assert_int_equal(encap_action_conf->size, sizeof(struct rte_ether_hdr) + ip_hdr_size + sizeof(struct rte_udp_hdr) + sizeof(struct rte_mpls_hdr));

    assert_memory_equal(ether_hdr->s_addr.addr_bytes, dst_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_memory_equal(ether_hdr->d_addr.addr_bytes, dst_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    assert_int_equal(mpls_hdr->tag_msb, RTE_BE16((mpls_label >> 4) & 0xffff));
    assert_int_equal(mpls_hdr->tag_lsb, mpls_label & 0xf);

    struct rte_flow_action_port_id *port_action_conf =
        (struct rte_flow_action_port_id *)
            flow_package.actions[ACTION_PORT_ID].conf;

    assert_int_equal(port_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_encap_udp_ipv6_l3(void **state)
{
    /**** GIVEN ****/

    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 3;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_phy = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &dst_phy_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_L2_RCV,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    const uint16_t outer_src_port = RTE_BE16(60486);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0xde, 0xad, 0xc0, 0xde, 0x00 },
        .eth_dmac = { 0x00, 0xde, 0xad, 0xbe, 0xef, 0x00 },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_family = AF_INET,
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const rte_le32_t mpls_label = RTE_LE32(31);

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t src_mac[VR_ETHER_ALEN] = { 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x00 };
    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
    };

    memcpy(metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV6
        },
        .proto = VR_IP_PROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    memcpy(flow.ip.src.ipv6, src_ip, VR_IP6_ADDRESS_LEN);
    memcpy(flow.ip.dst.ipv6, dst_ip, VR_IP6_ADDRESS_LEN);

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_phy,
        .dst_nh = &dst_nh.nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .route_traffic = true,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    /**** WHEN ****/

    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    /**** THEN ****/

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        RTE_FLOW_ACTION_TYPE_DEC_TTL,
        RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV6,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    // verify patterns

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv6 *ipv6_spec =
        (struct rte_flow_item_ipv6 *)flow_package.pattern[PATTERN_IPV6].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes, metadata.inner_src_mac, VR_ETHER_ALEN);
    assert_memory_equal(
        eth_spec->dst.addr_bytes, metadata.inner_dst_mac, VR_ETHER_ALEN);
    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_memory_equal(ipv6_spec->hdr.src_addr, src_ip, VR_IP6_ADDRESS_LEN);
    assert_memory_equal(ipv6_spec->hdr.dst_addr, dst_ip, VR_IP6_ADDRESS_LEN);
    assert_int_equal(ipv6_spec->hdr.proto, VR_IP_PROTO_UDP);


    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

    // verify actions

    struct rte_flow_action_raw_decap *decap_action_conf =
        (struct rte_flow_action_raw_decap *)
            flow_package.actions[ACTION_RAW_DECAP].conf;

    struct rte_ether_hdr *hdr = (struct rte_ether_hdr *)(decap_action_conf->data);
    assert_memory_equal(
        hdr->s_addr.addr_bytes, src_mac, VR_ETHER_ALEN);
    assert_memory_equal(
        hdr->d_addr.addr_bytes, dst_mac, VR_ETHER_ALEN);
    assert_int_equal(hdr->ether_type, RTE_BE16(RTE_ETHER_TYPE_IPV4));

    struct rte_flow_action_raw_encap *encap_action_conf =
        (struct rte_flow_action_raw_encap *)
            flow_package.actions[ACTION_RAW_ENCAP].conf;

    assert_non_null(encap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)encap_action_conf->data;

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(ether_hdr + 1);
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    assert_non_null(encap_action_conf->data);
    assert_null(encap_action_conf->preserve);
    assert_int_equal(encap_action_conf->size, sizeof(struct rte_ether_hdr) + ip_hdr_size + sizeof(struct rte_udp_hdr) + sizeof(struct rte_mpls_hdr));

    assert_memory_equal(ether_hdr->s_addr.addr_bytes, dst_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_memory_equal(ether_hdr->d_addr.addr_bytes, dst_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_int_equal(ether_hdr->ether_type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT));

    assert_int_equal(mpls_hdr->tag_msb, RTE_BE16((mpls_label >> 4) & 0xffff));
    assert_int_equal(mpls_hdr->tag_lsb, mpls_label & 0xf);

    struct rte_flow_action_port_id *port_action_conf =
        (struct rte_flow_action_port_id *)
            flow_package.actions[ACTION_PORT_ID].conf;

    assert_int_equal(port_action_conf->id, dst_port_id);
}

static void
test_mpls_o_udp_decap_udp_ipv6_l3(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_phy = 3;
    const uint32_t dst_port_id = 5;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_phy,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_phy = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_phy_ethdev,
    };

    const ipv4_t outer_src_ip = { { 1, 2, 3, 4 } };
    const ipv4_t outer_dst_ip = { { 5, 6, 7, 8 } };

    struct vr_eth src_nh_data = {
        .eth_smac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
        .eth_dmac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_UDP_MPLS,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_dst_ip.value,
                    .tun_dip = outer_src_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(src_nh.nh.nh_data, &src_nh_data, sizeof(src_nh_data));

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_ENCAP,
            .nh_family = AF_INET,
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    const uint16_t outer_src_port = RTE_BE16(60486);
    const uint16_t outer_dst_port = RTE_BE16(VR_MPLS_OVER_UDP_DST_PORT);

    const rte_le32_t mpls_label = RTE_LE32(31);

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = false,
    };

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    const uint8_t dst_mac[VR_ETHER_ALEN] = { 0x00, 0xde, 0xad, 0xde, 0xad, 0x00 };

    memcpy(dst_nh.nh.nh_data, dst_mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_FORWARD,
        .ip = {
            .type = VR_N3K_IP_TYPE_IPV6
        },
        .proto = VR_IP_PROTO_UDP,
        .src_port = src_port,
        .dst_port = dst_port,
        .tunnel_udp_src_port = outer_src_port,
    };

    memcpy(flow.ip.src.ipv6, src_ip, VR_IP6_ADDRESS_LEN);
    memcpy(flow.ip.dst.ipv6, dst_ip, VR_IP6_ADDRESS_LEN);

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh.nh,
        .dst_vif = &dst_phy,
        .dst_nh = &dst_nh.nh,
        .pkt_metadata = metadata,
        .flow = &flow,
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLSOUDP,
        .tunnel_label = mpls_label,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_RAW_DECAP,
        RTE_FLOW_ACTION_TYPE_RAW_ENCAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_MPLS,
        RTE_FLOW_ITEM_TYPE_IPV6,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END,
    };

    /* WHEN vr_n3k_offload_entry is converted to rte_flow */
    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);

    /* THEN rte_flow matches specified traffic */
    assert_int_equal(flow_package.error, 0);
    assert_non_null(flow_package.pattern);
    assert_non_null(flow_package.actions);

    assert_true(cmp_actions(flow_package.actions, actions));
    assert_true(cmp_patterns(flow_package.pattern, patterns));

    struct rte_flow_item_port_id *port_id_spec =
        (struct rte_flow_item_port_id *)flow_package.pattern[PATTERN_PORT_ID].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_mpls *mpls_spec =
        (struct rte_flow_item_mpls *)flow_package.pattern[PATTERN_MPLS].spec;

    struct rte_flow_item_ipv6 *ipv6_spec =
        (struct rte_flow_item_ipv6 *)flow_package.pattern[PATTERN_IPV6].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    assert_int_equal(port_id_spec->id, src_port_phy);

    assert_memory_equal(
        outer_eth_spec->src.addr_bytes, src_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_memory_equal(
        outer_eth_spec->dst.addr_bytes, src_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_int_equal(outer_eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(outer_ipv4_spec->hdr.src_addr, outer_src_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.dst_addr, outer_dst_ip.value);
    assert_int_equal(outer_ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(outer_udp_spec->hdr.src_port, outer_src_port);
    assert_int_equal(outer_udp_spec->hdr.dst_port, outer_dst_port);

    const rte_be32_t mpls_label_conv = RTE_BE32((mpls_label & VR_MPLS_LABEL_MASK) << VR_MPLS_LABEL_SHIFT);
    assert_memory_equal(mpls_spec->label_tc_s, &mpls_label_conv, 3);

    assert_memory_equal(ipv6_spec->hdr.src_addr, src_ip, VR_IP6_ADDRESS_LEN);
    assert_memory_equal(ipv6_spec->hdr.dst_addr, dst_ip, VR_IP6_ADDRESS_LEN);
    assert_int_equal(ipv6_spec->hdr.proto, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

    // verify actions

    struct rte_flow_action_raw_decap *decap_action_conf =
        (struct rte_flow_action_raw_decap *)flow_package.actions[ACTION_RAW_DECAP].conf;

    assert_non_null(decap_action_conf->data);

    struct rte_ipv4_hdr *ip_hdr = (struct rte_ipv4_hdr *)(
        decap_action_conf->data + sizeof(struct rte_ether_hdr));
    uint64_t ip_hdr_size = (ip_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;

    struct rte_udp_hdr *udp_hdr = (struct rte_udp_hdr *)((uint8_t *)ip_hdr + ip_hdr_size);

    struct rte_mpls_hdr *mpls_hdr = (struct rte_mpls_hdr *)(udp_hdr + 1);

    assert_int_equal(
        decap_action_conf->size,
        sizeof(struct rte_ether_hdr) +
            ip_hdr_size +
            sizeof(struct rte_udp_hdr) +
            sizeof(struct rte_mpls_hdr)
    );

    assert_int_equal(ip_hdr->src_addr, outer_src_ip.value);
    assert_int_equal(ip_hdr->dst_addr, outer_dst_ip.value);
    assert_int_equal(ip_hdr->next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_hdr->src_port, outer_src_port);
    assert_int_equal(udp_hdr->dst_port, outer_dst_port);

    rte_le32_t result_label_msb = rte_be_to_cpu_16(mpls_hdr->tag_msb);
    rte_le32_t result_label = mpls_hdr->tag_lsb | (result_label_msb << 4);
    assert_int_equal(result_label, mpls_label);

    struct rte_flow_action_raw_encap *encap_action_conf =
        (struct rte_flow_action_raw_encap *)flow_package.actions[ACTION_RAW_ENCAP].conf;

    assert_non_null(encap_action_conf->data);

    struct rte_ether_hdr *ether_hdr = (struct rte_ether_hdr *)encap_action_conf->data;

    assert_memory_equal(ether_hdr->s_addr.addr_bytes, VROUTER_MAC, VR_ETHER_ALEN);
    assert_memory_equal(ether_hdr->d_addr.addr_bytes, dst_mac, VR_ETHER_ALEN);

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)flow_package.actions[ACTION_PORT_ID].conf;

    assert_non_null(decap_action_conf-> data);
    assert_int_equal(port_id_action_conf->id, dst_port_id);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_mpls_o_udp_decap_tcp),
        cmocka_unit_test(test_mpls_o_udp_decap_udp),
        cmocka_unit_test(test_mpls_o_udp_encap_tcp),
        cmocka_unit_test(test_mpls_o_udp_encap_udp),
        cmocka_unit_test(test_mpls_o_udp_encap_udp_l3),
        cmocka_unit_test(test_mpls_o_udp_decap_udp_l3),
        cmocka_unit_test(test_mpls_o_udp_decap_tcp_ipv6),
        cmocka_unit_test(test_mpls_o_udp_decap_udp_ipv6),
        cmocka_unit_test(test_mpls_o_udp_encap_tcp_ipv6),
        cmocka_unit_test(test_mpls_o_udp_encap_udp_ipv6),
        cmocka_unit_test(test_mpls_o_udp_encap_udp_ipv6_l3),
        cmocka_unit_test(test_mpls_o_udp_decap_udp_ipv6_l3),
    };

    return cmocka_run_group_tests_name("test_mpls_o_udp_decap", tests, NULL, NULL);
}
