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
#include <vr_dpdk_n3k_packet_metadata.h>

#include <vr_packet.h>
#include <vr_nexthop.h>

#include "flow_test_utils.h"

/*
 * same_cn: flow is created between vms on the same compute node
 * same_net: vms are attached to the same network.
 */

static void
test_same_cn_same_net_forward(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 6;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_vf_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_vf_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_ENCAP,
    };

    struct vr_nexthop dst_nh = {
        .nh_type = NH_ENCAP,
    };

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
    };

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_vf,
        .dst_nh = &dst_nh,
        .pkt_metadata = metadata,
        .flow = &flow,
    };

    enum rte_flow_action_type actions[] = {
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

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)find_action(
            flow_package.actions, RTE_FLOW_ACTION_TYPE_PORT_ID)->conf;
    assert_int_equal(port_id_action_conf->id, dst_port_id);
}

static void
test_same_cn_same_net_drop(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_id = 1;
    const uint16_t dst_port_id = 2;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_vf_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_vf_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_ENCAP,
    };

    struct vr_nexthop dst_nh = {
        .nh_type = NH_ENCAP,
    };

    struct vr_dpdk_n3k_packet_metadata metadata = {
        .eth_hdr_present = true,
        .inner_src_mac = { 0xde, 0xad, 0xc0, 0xde, 0x00, 0x01 },
        .inner_dst_mac = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x02 },
    };

    const ipv4_t src_ip = { { 12, 10, 0, 7 } };
    const ipv4_t dst_ip = { { 12, 10, 0, 9 } };

    const uint16_t src_port = RTE_BE16(4444);
    const uint16_t dst_port = RTE_BE16(1234);

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
    };

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_vf,
        .dst_nh = &dst_nh,
        .pkt_metadata = metadata,
        .flow = &flow,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_DROP,
        RTE_FLOW_ACTION_TYPE_END
    };

    enum rte_flow_item_type patterns[] = {
        RTE_FLOW_ITEM_TYPE_PORT_ID,
        RTE_FLOW_ITEM_TYPE_ETH,
        RTE_FLOW_ITEM_TYPE_IPV4,
        RTE_FLOW_ITEM_TYPE_UDP,
        RTE_FLOW_ITEM_TYPE_END
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
test_same_cn_same_net_ipv6_forward(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 6;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_vf_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_vf_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_ENCAP,
    };

    struct vr_nexthop dst_nh = {
        .nh_type = NH_ENCAP,
    };

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
    };

    memcpy(flow.ip.src.ipv6, src_ip, VR_IP6_ADDRESS_LEN);
    memcpy(flow.ip.dst.ipv6, dst_ip, VR_IP6_ADDRESS_LEN);

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_vf,
        .dst_nh = &dst_nh,
        .pkt_metadata = metadata,
        .flow = &flow,
    };

    enum rte_flow_action_type actions[] = {
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

    struct rte_flow_action_port_id *port_id_action_conf =
        (struct rte_flow_action_port_id *)find_action(
            flow_package.actions, RTE_FLOW_ACTION_TYPE_PORT_ID)->conf;
    assert_int_equal(port_id_action_conf->id, dst_port_id);
}

static void
test_same_cn_same_net_ipv6_drop(void **state)
{
    /* GIVEN vr_n3k_offload_entry definition */
    const uint16_t src_port_id = 5;
    const uint16_t dst_port_id = 6;

    struct vr_dpdk_ethdev src_vf_ethdev = {
        .ethdev_port_id = src_port_id,
    };
    struct vr_interface src_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &src_vf_ethdev,
    };

    struct vr_dpdk_ethdev dst_vf_ethdev = {
        .ethdev_port_id = dst_port_id,
    };
    struct vr_interface dst_vf = {
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_os = &dst_vf_ethdev,
    };

    struct vr_nexthop src_nh = {
        .nh_type = NH_ENCAP,
    };

    struct vr_nexthop dst_nh = {
        .nh_type = NH_ENCAP,
    };

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
    };

    memcpy(flow.ip.src.ipv6, src_ip, VR_IP6_ADDRESS_LEN);
    memcpy(flow.ip.dst.ipv6, dst_ip, VR_IP6_ADDRESS_LEN);

    struct vr_n3k_offload_entry offload_entry = {
        .src_vif = &src_vf,
        .src_nh = &src_nh,
        .dst_vif = &dst_vf,
        .dst_nh = &dst_nh,
        .pkt_metadata = metadata,
        .flow = &flow,
    };

    enum rte_flow_action_type actions[] = {
        RTE_FLOW_ACTION_TYPE_DROP,
        RTE_FLOW_ACTION_TYPE_END
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

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_same_cn_same_net_forward),
        cmocka_unit_test(test_same_cn_same_net_drop),
        cmocka_unit_test(test_same_cn_same_net_ipv6_forward),
        cmocka_unit_test(test_same_cn_same_net_ipv6_drop),
    };

    return cmocka_run_group_tests_name(
        "vr_dpdk_n3k_flow_convert_simple_udp", tests, NULL, NULL);
}
