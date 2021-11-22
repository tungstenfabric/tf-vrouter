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

#include <rte_flow.h>

#include <offload_entry/vr_dpdk_n3k_offload_entry.h>
#include <offload_entry/vr_dpdk_n3k_offload_converter.h>
#include <offload_entry/vr_dpdk_n3k_rte_flow_defs.h>

#include <vr_dpdk_n3k_flow.h>
#include <vr_dpdk_n3k_interface.h>
#include <vr_dpdk_n3k_nexthop.h>
#include <vr_dpdk_n3k_vxlan.h>
#include <vr_dpdk_n3k_packet_metadata.h>

#include <vr_packet.h>
#include <vr_nexthop.h>
#include <vr_vxlan.h>

#include "flow_test_utils.h"

/*
 * 2_cn: flow is created between vms on two different compute nodes
 * same_net: vms are attached to the same network.
 */

static void
test_2_cn_same_net_encap_forward(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_id = 3;
    const uint16_t dst_port_id = 5;

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

    const uint16_t outer_src_port = RTE_BE16(911);
    const uint16_t outer_dst_port = RTE_BE16(4789);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa },
        .eth_dmac = { 0x00, 0x10, 0xbb, 0xbb, 0xbb, 0xbb },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_VXLAN,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const uint32_t vxlan_vnid = 13;

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
    };

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

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
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN,
        .tunnel_label = vxlan_vnid,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP,
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

    struct rte_flow_action_vxlan_encap *encap_action_conf =
        (struct rte_flow_action_vxlan_encap *)find_action(
            flow_package.actions, RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP)->conf;

    struct rte_flow_item_eth *encap_eth_spec =
        (struct rte_flow_item_eth *)
            encap_action_conf->definition[ENCAP_ETH].spec;

    struct rte_flow_item_ipv4 *encap_ipv4_spec =
        (struct rte_flow_item_ipv4 *)
            encap_action_conf->definition[ENCAP_IPV4].spec;

    struct rte_flow_item_udp *encap_udp_spec =
        (struct rte_flow_item_udp *)
            encap_action_conf->definition[ENCAP_UDP].spec;

    struct rte_flow_item_vxlan *encap_vxlan_spec =
        (struct rte_flow_item_vxlan *)
            encap_action_conf->definition[ENCAP_VXLAN].spec;

    assert_int_equal(
        encap_action_conf->definition[ENCAP_ETH].type,
        RTE_FLOW_ITEM_TYPE_ETH
    );

    assert_int_equal(
        encap_action_conf->definition[ENCAP_IPV4].type,
        RTE_FLOW_ITEM_TYPE_IPV4
    );

    assert_int_equal(
        encap_action_conf->definition[ENCAP_UDP].type,
        RTE_FLOW_ITEM_TYPE_UDP
    );

    assert_int_equal(
        encap_action_conf->definition[ENCAP_VXLAN].type,
        RTE_FLOW_ITEM_TYPE_VXLAN
    );

    assert_int_equal(
        encap_action_conf->definition[ENCAP_END].type,
        RTE_FLOW_ITEM_TYPE_END
    );

    assert_memory_equal(
        encap_eth_spec->src.addr_bytes, dst_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_memory_equal(
        encap_eth_spec->dst.addr_bytes, dst_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_int_equal(encap_eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(encap_ipv4_spec->hdr.src_addr, outer_src_ip.value);
    assert_int_equal(encap_ipv4_spec->hdr.dst_addr, outer_dst_ip.value);
    assert_int_equal(encap_ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(encap_udp_spec->hdr.src_port, outer_src_port);
    assert_int_equal(encap_udp_spec->hdr.dst_port, outer_dst_port);

    uint32_t vni = 0;
    memcpy(&vni, encap_vxlan_spec->vni, sizeof(encap_vxlan_spec->vni));
    assert_int_equal(
        vni & VXLAN_MASK,
        RTE_BE32(vxlan_vnid << VR_VXLAN_VNID_SHIFT) & VXLAN_MASK
    );

    struct rte_flow_action_port_id *port_action_conf =
        (struct rte_flow_action_port_id *)find_action(
            flow_package.actions, RTE_FLOW_ACTION_TYPE_PORT_ID)->conf;

    assert_int_equal(port_action_conf->id, dst_port_id);
}

static void
test_2_cn_same_net_encap_drop(void **state)
{
        /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_id = 3;
    const uint16_t dst_port_id = 5;

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

    const uint16_t outer_src_port = RTE_BE16(911);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa },
        .eth_dmac = { 0x00, 0x10, 0xbb, 0xbb, 0xbb, 0xbb },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_VXLAN,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const uint32_t vxlan_vnid = 13;

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
    };

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_DROP,
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
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN,
        .tunnel_label = vxlan_vnid,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_DROP,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
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
}

static void
test_2_cn_same_net_decap_forward(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint32_t src_port_id = 3;
    const uint16_t dst_port_id = 2;

    struct vr_dpdk_ethdev src_phy_ethdev = {
        .ethdev_port_id = src_port_id,
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
        .eth_smac = { 0x00, 0x10, 0xbb, 0xbb, 0xbb, 0xbb },
        .eth_dmac = { 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_VXLAN,

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

    const uint16_t outer_src_port = RTE_BE16(911);
    const uint16_t outer_dst_port = RTE_BE16(4789);

    const uint32_t vxlan_vnid = 13;

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
    };

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

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
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN,
        .tunnel_label = vxlan_vnid,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_VXLAN_DECAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_VXLAN,
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

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv4 *ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_IPV4].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_vxlan *vxlan_spec =
        (struct rte_flow_item_vxlan *)flow_package.pattern[PATTERN_VXLAN].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes,
        metadata.inner_src_mac,
        VR_ETHER_ALEN
    );

    assert_memory_equal(
        eth_spec->dst.addr_bytes,
        metadata.inner_dst_mac,
        VR_ETHER_ALEN
    );

    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ipv4_spec->hdr.src_addr, src_ip.value);
    assert_int_equal(ipv4_spec->hdr.dst_addr, dst_ip.value);
    assert_int_equal(ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

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

    uint32_t vni = 0;
    memcpy(&vni, vxlan_spec->vni, sizeof(vxlan_spec->vni));
    assert_int_equal(
        vni & VXLAN_MASK,
        RTE_BE32(vxlan_vnid << VR_VXLAN_VNID_SHIFT) & VXLAN_MASK
    );

    struct rte_flow_action_port_id *vf_action_conf =
        (struct rte_flow_action_port_id *)find_action(
            flow_package.actions, RTE_FLOW_ACTION_TYPE_PORT_ID)->conf;

    assert_int_equal(vf_action_conf->id, dst_port_id);
}

static void
test_2_cn_same_net_decap_drop(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint32_t src_port_id = 3;
    const uint16_t dst_port_id = 2;

    struct vr_dpdk_ethdev src_phy_ethdev = {
        .ethdev_port_id = src_port_id,
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
        .eth_smac = { 0x00, 0x10, 0xbb, 0xbb, 0xbb, 0xbb },
        .eth_dmac = { 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_VXLAN,

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

    const uint16_t outer_src_port = RTE_BE16(911);
    const uint16_t outer_dst_port = RTE_BE16(4789);

    const uint32_t vxlan_vnid = 13;

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
    };

    const ipv4_t src_ip = { { 12, 10, 0, 4 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 5 } };

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_DROP,
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
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN,
        .tunnel_label = vxlan_vnid,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_DROP,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_VXLAN,
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

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv4 *ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_IPV4].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_vxlan *vxlan_spec =
        (struct rte_flow_item_vxlan *)flow_package.pattern[PATTERN_VXLAN].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes,
        metadata.inner_src_mac,
        VR_ETHER_ALEN
    );

    assert_memory_equal(
        eth_spec->dst.addr_bytes,
        metadata.inner_dst_mac,
        VR_ETHER_ALEN
    );

    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(ipv4_spec->hdr.src_addr, src_ip.value);
    assert_int_equal(ipv4_spec->hdr.dst_addr, dst_ip.value);
    assert_int_equal(ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

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

    uint32_t vni = 0;
    memcpy(&vni, vxlan_spec->vni, sizeof(vxlan_spec->vni));
    assert_int_equal(
        vni & VXLAN_MASK,
        RTE_BE32(vxlan_vnid << VR_VXLAN_VNID_SHIFT) & VXLAN_MASK
    );
}


static void
test_2_cn_same_net_encap_ipv6_forward(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_id = 3;
    const uint16_t dst_port_id = 5;

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

    const uint16_t outer_src_port = RTE_BE16(911);
    const uint16_t outer_dst_port = RTE_BE16(4789);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa },
        .eth_dmac = { 0x00, 0x10, 0xbb, 0xbb, 0xbb, 0xbb },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_VXLAN,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const uint32_t vxlan_vnid = 13;

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
    };

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

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
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN,
        .tunnel_label = vxlan_vnid,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP,
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

    struct rte_flow_action_vxlan_encap *encap_action_conf =
        (struct rte_flow_action_vxlan_encap *)find_action(
            flow_package.actions, RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP)->conf;

    struct rte_flow_item_eth *encap_eth_spec =
        (struct rte_flow_item_eth *)
            encap_action_conf->definition[ENCAP_ETH].spec;

    struct rte_flow_item_ipv4 *encap_ipv4_spec =
        (struct rte_flow_item_ipv4 *)
            encap_action_conf->definition[ENCAP_IPV4].spec;

    struct rte_flow_item_udp *encap_udp_spec =
        (struct rte_flow_item_udp *)
            encap_action_conf->definition[ENCAP_UDP].spec;

    struct rte_flow_item_vxlan *encap_vxlan_spec =
        (struct rte_flow_item_vxlan *)
            encap_action_conf->definition[ENCAP_VXLAN].spec;

    assert_int_equal(
        encap_action_conf->definition[ENCAP_ETH].type,
        RTE_FLOW_ITEM_TYPE_ETH
    );

    assert_int_equal(
        encap_action_conf->definition[ENCAP_IPV4].type,
        RTE_FLOW_ITEM_TYPE_IPV4
    );

    assert_int_equal(
        encap_action_conf->definition[ENCAP_UDP].type,
        RTE_FLOW_ITEM_TYPE_UDP
    );

    assert_int_equal(
        encap_action_conf->definition[ENCAP_VXLAN].type,
        RTE_FLOW_ITEM_TYPE_VXLAN
    );

    assert_int_equal(
        encap_action_conf->definition[ENCAP_END].type,
        RTE_FLOW_ITEM_TYPE_END
    );

    assert_memory_equal(
        encap_eth_spec->src.addr_bytes, dst_nh_data.eth_smac, VR_ETHER_ALEN);
    assert_memory_equal(
        encap_eth_spec->dst.addr_bytes, dst_nh_data.eth_dmac, VR_ETHER_ALEN);
    assert_int_equal(encap_eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_int_equal(encap_ipv4_spec->hdr.src_addr, outer_src_ip.value);
    assert_int_equal(encap_ipv4_spec->hdr.dst_addr, outer_dst_ip.value);
    assert_int_equal(encap_ipv4_spec->hdr.next_proto_id, VR_IP_PROTO_UDP);

    assert_int_equal(encap_udp_spec->hdr.src_port, outer_src_port);
    assert_int_equal(encap_udp_spec->hdr.dst_port, outer_dst_port);

    uint32_t vni = 0;
    memcpy(&vni, encap_vxlan_spec->vni, sizeof(encap_vxlan_spec->vni));
    assert_int_equal(
        vni & VXLAN_MASK,
        RTE_BE32(vxlan_vnid << VR_VXLAN_VNID_SHIFT) & VXLAN_MASK
    );

    struct rte_flow_action_port_id *port_action_conf =
        (struct rte_flow_action_port_id *)find_action(
            flow_package.actions, RTE_FLOW_ACTION_TYPE_PORT_ID)->conf;

    assert_int_equal(port_action_conf->id, dst_port_id);
}

static void
test_2_cn_same_net_encap_ipv6_drop(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_id = 3;
    const uint32_t dst_port_phy = 5;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_phy_ethdev = {
        .ethdev_port_id = dst_port_phy,
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

    const uint16_t outer_src_port = RTE_BE16(911);

    struct vr_eth dst_nh_data = {
        .eth_smac = { 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa },
        .eth_dmac = { 0x00, 0x10, 0xbb, 0xbb, 0xbb, 0xbb },
    };

    struct vr_nexthop_with_data dst_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_VXLAN,

            .nh_u = {
                .nh_udp_tun = {
                    .tun_sip = outer_src_ip.value,
                    .tun_dip = outer_dst_ip.value,
                }
            },
            .nh_data_size = sizeof (struct vr_eth),
        },
    };

    memcpy(dst_nh.nh.nh_data, &dst_nh_data, sizeof(dst_nh_data));

    const uint32_t vxlan_vnid = 13;

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
    };

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_DROP,
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
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN,
        .tunnel_label = vxlan_vnid,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_DROP,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
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
}

static void
test_2_cn_same_net_decap_ipv6_forward(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint32_t src_port_id = 3;
    const uint16_t dst_port_id = 2;

    struct vr_dpdk_ethdev src_phy_ethdev = {
        .ethdev_port_id = src_port_id,
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
        .eth_smac = { 0x00, 0x10, 0xbb, 0xbb, 0xbb, 0xbb },
        .eth_dmac = { 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_VXLAN,

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

    const uint16_t outer_src_port = RTE_BE16(911);
    const uint16_t outer_dst_port = RTE_BE16(4789);

    const uint32_t vxlan_vnid = 13;

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
    };

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

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
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN,
        .tunnel_label = vxlan_vnid,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_VXLAN_DECAP,
        RTE_FLOW_ACTION_TYPE_PORT_ID,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_VXLAN,
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

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv6 *ipv6_spec =
        (struct rte_flow_item_ipv6 *)flow_package.pattern[PATTERN_IPV6].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_vxlan *vxlan_spec =
        (struct rte_flow_item_vxlan *)flow_package.pattern[PATTERN_VXLAN].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes,
        metadata.inner_src_mac,
        VR_ETHER_ALEN
    );

    assert_memory_equal(
        eth_spec->dst.addr_bytes,
        metadata.inner_dst_mac,
        VR_ETHER_ALEN
    );

    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_memory_equal(ipv6_spec->hdr.src_addr, src_ip, VR_IP6_ADDRESS_LEN);
    assert_memory_equal(ipv6_spec->hdr.dst_addr, dst_ip, VR_IP6_ADDRESS_LEN);
    assert_int_equal(ipv6_spec->hdr.proto, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

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

    uint32_t vni = 0;
    memcpy(&vni, vxlan_spec->vni, sizeof(vxlan_spec->vni));
    assert_int_equal(
        vni & VXLAN_MASK,
        RTE_BE32(vxlan_vnid << VR_VXLAN_VNID_SHIFT) & VXLAN_MASK
    );

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)find_action(
            flow_package.actions, RTE_FLOW_ACTION_TYPE_PORT_ID)->conf;

    assert_int_equal(port_id_action_conf->id, dst_port_id);
}

static void
test_2_cn_same_net_decap_ipv6_drop(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint32_t src_port_id = 3;
    const uint16_t dst_port_id = 2;

    struct vr_dpdk_ethdev src_phy_ethdev = {
        .ethdev_port_id = src_port_id,
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
        .eth_smac = { 0x00, 0x10, 0xbb, 0xbb, 0xbb, 0xbb },
        .eth_dmac = { 0x00, 0x10, 0xaa, 0xaa, 0xaa, 0xaa },
    };

    struct vr_nexthop_with_data src_nh = {
        .nh = {
            .nh_type = NH_TUNNEL,
            .nh_flags = NH_FLAG_TUNNEL_VXLAN,

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

    const uint16_t outer_src_port = RTE_BE16(911);
    const uint16_t outer_dst_port = RTE_BE16(4789);

    const uint32_t vxlan_vnid = 13;

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x00 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x00 },
    };

    const uint8_t src_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x04";
    const uint8_t dst_ip[VR_IP6_ADDRESS_LEN] =
        "\x12\x10\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x05";

    const uint16_t src_port = RTE_BE16(12345);
    const uint16_t dst_port = RTE_BE16(6666);

    struct vr_n3k_offload_flow flow = {
        .action = VR_FLOW_ACTION_DROP,
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
        .tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN,
        .tunnel_label = vxlan_vnid,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_DROP,
        RTE_FLOW_ACTION_TYPE_END,
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_VXLAN,
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

    struct rte_flow_item_eth *eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_ETH].spec;

    struct rte_flow_item_ipv6 *ipv6_spec =
        (struct rte_flow_item_ipv6 *)flow_package.pattern[PATTERN_IPV6].spec;

    struct rte_flow_item_udp *udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_UDP].spec;

    struct rte_flow_item_eth *outer_eth_spec =
        (struct rte_flow_item_eth *)flow_package.pattern[PATTERN_OUTER_ETH].spec;

    struct rte_flow_item_ipv4 *outer_ipv4_spec =
        (struct rte_flow_item_ipv4 *)flow_package.pattern[PATTERN_OUTER_IPV4].spec;

    struct rte_flow_item_udp *outer_udp_spec =
        (struct rte_flow_item_udp *)flow_package.pattern[PATTERN_OUTER_UDP].spec;

    struct rte_flow_item_vxlan *vxlan_spec =
        (struct rte_flow_item_vxlan *)flow_package.pattern[PATTERN_VXLAN].spec;

    assert_int_equal(port_id_spec->id, src_port_id);

    assert_memory_equal(
        eth_spec->src.addr_bytes,
        metadata.inner_src_mac,
        VR_ETHER_ALEN
    );

    assert_memory_equal(
        eth_spec->dst.addr_bytes,
        metadata.inner_dst_mac,
        VR_ETHER_ALEN
    );

    assert_int_equal(eth_spec->type, RTE_BE16(VR_ETH_PROTO_IP));

    assert_memory_equal(ipv6_spec->hdr.src_addr, src_ip, VR_IP6_ADDRESS_LEN);
    assert_memory_equal(ipv6_spec->hdr.dst_addr, dst_ip, VR_IP6_ADDRESS_LEN);
    assert_int_equal(ipv6_spec->hdr.proto, VR_IP_PROTO_UDP);

    assert_int_equal(udp_spec->hdr.src_port, src_port);
    assert_int_equal(udp_spec->hdr.dst_port, dst_port);

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

    uint32_t vni = 0;
    memcpy(&vni, vxlan_spec->vni, sizeof(vxlan_spec->vni));
    assert_int_equal(
        vni & VXLAN_MASK,
        RTE_BE32(vxlan_vnid << VR_VXLAN_VNID_SHIFT) & VXLAN_MASK
    );
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_2_cn_same_net_encap_forward),
        cmocka_unit_test(test_2_cn_same_net_encap_drop),
        cmocka_unit_test(test_2_cn_same_net_decap_forward),
        cmocka_unit_test(test_2_cn_same_net_decap_drop),
        cmocka_unit_test(test_2_cn_same_net_encap_ipv6_forward),
        cmocka_unit_test(test_2_cn_same_net_encap_ipv6_drop),
        cmocka_unit_test(test_2_cn_same_net_decap_ipv6_forward),
        cmocka_unit_test(test_2_cn_same_net_decap_ipv6_drop),
    };

    return cmocka_run_group_tests_name(
        "vr_dpdk_n3k_flow_convert_vxlan_udp", tests, NULL, NULL);
}
