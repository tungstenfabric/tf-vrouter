/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <errno.h>

#include <rte_common.h>

#include <vr_interface.h>
#include <vr_nexthop.h>
#include <vr_packet.h>

#include <vr_dpdk_n3k_packet_metadata.h>
#include <vr_dpdk_n3k_packet_parser.h>

#include "test_dpdk_n3k_packet_parse.h"

#include <cmocka.h>


#define GROUP_NAME "vr_dpdk_n3k_packet_parse"

static struct vr_interface test_interfaces[] = {
    {
        .vif_idx = 0,
        .vif_type = VIF_TYPE_PHYSICAL,
        .vif_nh_id = 1,
    },
    {
        .vif_idx = 1,
        .vif_type = VIF_TYPE_VIRTUAL,
        .vif_nh_id = 2,
    },
};

#define PHYSICAL_VIF (test_interfaces[0])
#define VIRTUAL_1_VIF (test_interfaces[1])

static struct vr_nexthop test_nexthops[] = {
    {
        .nh_id = 0,
        .nh_type = NH_DISCARD,
    },
    {
        .nh_id = 1,
        .nh_type = NH_ENCAP,
        .nh_family = AF_INET,
        .nh_dev = &test_interfaces[0],
    },
    {
        .nh_id = 2,
        .nh_type = NH_ENCAP,
        .nh_family = AF_INET,
        .nh_dev = &test_interfaces[1],
    },
    {
        .nh_id = 3,
        .nh_type = NH_ENCAP,
        .nh_family = AF_BRIDGE,
        .nh_dev = &test_interfaces[1],
    },
};



static void
test_parse_packet_key_from_udp_on_vm_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &VIRTUAL_1_VIF,
        .vp_nh = &test_nexthops[VIRTUAL_1_VIF.vif_nh_id],
        .vp_head = (uint8_t *)(&test_udp_packets[0]),
        .vp_data = 0,
    };
    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;
    memset(&key, 0, sizeof(key));
    memset(&metadata, 0, sizeof(metadata));

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);
    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.src_ip, RTE_IPV4(192, 168, 0, 1));
    assert_int_equal(key.dst_ip, RTE_IPV4(192, 168, 0, 2));
    assert_int_equal(key.proto, VR_IP_PROTO_UDP);
    assert_int_equal(key.src_port, rte_cpu_to_be_16(5555));
    assert_int_equal(key.dst_port, rte_cpu_to_be_16(6666));
}

static void
test_parse_packet_metadata_from_udp_on_vm_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &VIRTUAL_1_VIF,
        .vp_nh = &test_nexthops[VIRTUAL_1_VIF.vif_nh_id],
        .vp_head = (uint8_t *)(&test_udp_packets[0]),
        .vp_data = 0,
    };
    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;
    memset(&key, 0, sizeof(key));
    memset(&metadata, 0, sizeof(metadata));

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);
    assert_true(metadata.eth_hdr_present);
    assert_memory_equal(
        &metadata.inner_src_mac[0],
        &test_udp_packets[0].eth_hdr.s_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
    assert_memory_equal(
        &metadata.inner_dst_mac[0],
        &test_udp_packets[0].eth_hdr.d_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
}

static void
test_parse_packet_key_from_tcp_on_vm_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &VIRTUAL_1_VIF,
        .vp_nh = &test_nexthops[VIRTUAL_1_VIF.vif_nh_id],
        .vp_head = (uint8_t *)(&test_tcp_packets[0]),
        .vp_data = 0,
    };
    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;
    memset(&key, 0, sizeof(key));
    memset(&metadata, 0, sizeof(metadata));

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);
    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.src_ip, RTE_IPV4(192, 168, 0, 1));
    assert_int_equal(key.dst_ip, RTE_IPV4(192, 168, 0, 2));
    assert_int_equal(key.proto, VR_IP_PROTO_TCP);
    assert_int_equal(key.src_port, rte_cpu_to_be_16(5555));
    assert_int_equal(key.dst_port, rte_cpu_to_be_16(6666));
}

static void
test_parse_packet_metadata_from_tcp_on_vm_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &VIRTUAL_1_VIF,
        .vp_nh = &test_nexthops[VIRTUAL_1_VIF.vif_nh_id],
        .vp_head = (uint8_t *)(&test_tcp_packets[0]),
        .vp_data = 0,
    };
    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;
    memset(&key, 0, sizeof(key));
    memset(&metadata, 0, sizeof(metadata));

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);
    assert_true(metadata.eth_hdr_present);
    assert_memory_equal(
        &metadata.inner_src_mac[0],
        &test_tcp_packets[0].eth_hdr.s_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
    assert_memory_equal(
        &metadata.inner_dst_mac[0],
        &test_tcp_packets[0].eth_hdr.d_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
}

static void
test_parse_packet_fails_on_ipv6(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &VIRTUAL_1_VIF,
        .vp_nh = &test_nexthops[VIRTUAL_1_VIF.vif_nh_id],
        .vp_head = (uint8_t *)(&test_udp_packets[1]),
        .vp_data = 0,
    };
    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;
    memset(&key, 0, sizeof(key));
    memset(&metadata, 0, sizeof(metadata));

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, -EINVAL);
}

static void
test_parse_packet_fails_on_arp(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &VIRTUAL_1_VIF,
        .vp_nh = &test_nexthops[VIRTUAL_1_VIF.vif_nh_id],
        .vp_head = (uint8_t *)(&test_udp_packets[2]),
        .vp_data = 0,
    };
    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;
    memset(&key, 0, sizeof(key));
    memset(&metadata, 0, sizeof(metadata));

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, -EINVAL);
}


#define assert_returned_error(rc, expected) { \
    if ((rc) != (expected)) \
        fail_msg("Incorrect return value. Expected %d '%s', returned %d '%s'", \
            rc, strerror(-(rc)), expected, strerror(-(expected))); \
}

static void
test_parse_packet_returns_inval_on_ipv6_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_fabric_ether_ipv6_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -EINVAL);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_inval_on_arp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_fabric_ether_arp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -EINVAL);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_nosys_on_gre_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_fabric_ipv4_gre_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOSYS);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_inval_on_non_udp_tcp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_fabric_ipv4_icmp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -EINVAL);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_inval_on_unknown_udp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_fabric_ipv4_unknown_udp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -EINVAL);

    RTE_SET_USED(state);
}


int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_packet_key_from_udp_on_vm_rx),
        cmocka_unit_test(test_parse_packet_metadata_from_udp_on_vm_rx),
        cmocka_unit_test(test_parse_packet_key_from_tcp_on_vm_rx),
        cmocka_unit_test(test_parse_packet_metadata_from_tcp_on_vm_rx),
        cmocka_unit_test(test_parse_packet_fails_on_ipv6),
        cmocka_unit_test(test_parse_packet_fails_on_arp),
        /* FABRIC RX, L2=Ether, L3==?*/
        cmocka_unit_test(test_parse_packet_returns_inval_on_ipv6_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_inval_on_arp_on_fabric_rx),
        /* FABRIC RX, L2=Ether, L3==IPv4, L4=?*/
        cmocka_unit_test(test_parse_packet_returns_nosys_on_gre_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_inval_on_non_udp_tcp_on_fabric_rx),
        /* FABRIC RX, L2=Ether, L3==IPv4, L4=UDP */
        cmocka_unit_test(test_parse_packet_returns_inval_on_unknown_udp_on_fabric_rx),
    };

    return cmocka_run_group_tests_name(GROUP_NAME, tests, NULL, NULL);
}
