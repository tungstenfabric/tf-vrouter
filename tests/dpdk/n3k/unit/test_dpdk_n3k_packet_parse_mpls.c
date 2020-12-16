/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <vr_interface.h>
#include <vr_nexthop.h>
#include <vr_packet.h>

#include <vr_dpdk_n3k_mpls.h>
#include <vr_dpdk_n3k_packet_metadata.h>
#include <vr_dpdk_n3k_packet_parser.h>

/* Include packet data definitions. */
#include "test_dpdk_n3k_packet_parse_mpls.h"

#define GROUP_NAME "vr_dpdk_n3k_packet_parse_mpls"

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

static struct vr_n3k_offload_mpls mpls_offload_entries[] = {
    {
        .label = 31,
        .nexthop_id = 3,
    },
    {
        .label = 28,
        .nexthop_id = 2,
    },
};

#define MPLS_OFF_L2 (mpls_offload_entries[0])
#define MPLS_OFF_L3 (mpls_offload_entries[1])

struct vr_n3k_offload_mpls *
vr_dpdk_n3k_offload_mpls_get_by_label(uint32_t label)
{
    check_expected(label);
    return mock_ptr_type(struct vr_n3k_offload_mpls*);
}

int
vr_dpdk_n3k_is_nh_l2(uint32_t nh_id, bool *is_l2)
{
    check_expected(nh_id);
    assert_non_null(is_l2);
    *is_l2 = (bool)mock();
    return (int)mock();
}

int
vr_dpdk_n3k_get_key_nh_from_l2_nh(const uint32_t l2_nh_id,
        const rte_be32_t ip_addr, rte_le32_t *key_nh_id)
{
    check_expected(l2_nh_id);
    check_expected(ip_addr);
    *key_nh_id = (rte_le32_t)mock();
    return (int)mock();
}

static void
test_parse_packet_key_from_mpls_l2_udp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_udp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L2.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L2);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L2.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, true);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, l2_nh_id, MPLS_OFF_L2.nexthop_id);
    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, ip_addr,
        data_mpls_udp_packet.inner_ipv4_hdr.dst_addr);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.src_ip, data_mpls_udp_packet.inner_ipv4_hdr.src_addr);
    assert_int_equal(key.dst_ip, data_mpls_udp_packet.inner_ipv4_hdr.dst_addr);
    assert_int_equal(key.proto, IPPROTO_UDP);
    assert_int_equal(key.src_port, data_mpls_udp_packet.inner_udp_hdr.src_port);
    assert_int_equal(key.dst_port, data_mpls_udp_packet.inner_udp_hdr.dst_port);

    RTE_SET_USED(state);
}

static void
test_parse_packet_key_from_mpls_l3_udp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_udp_l3_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L3.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L3);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L3.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, false);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.src_ip, data_mpls_udp_l3_packet.inner_ipv4_hdr.src_addr);
    assert_int_equal(key.dst_ip, data_mpls_udp_l3_packet.inner_ipv4_hdr.dst_addr);
    assert_int_equal(key.proto, IPPROTO_UDP);
    assert_int_equal(key.src_port, data_mpls_udp_l3_packet.inner_udp_hdr.src_port);
    assert_int_equal(key.dst_port, data_mpls_udp_l3_packet.inner_udp_hdr.dst_port);

    RTE_SET_USED(state);
}

static void
test_parse_packet_key_from_mpls_l2_tcp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_tcp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L2.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L2);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L2.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, true);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, l2_nh_id, MPLS_OFF_L2.nexthop_id);
    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, ip_addr,
        data_mpls_tcp_packet.inner_ipv4_hdr.dst_addr);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.src_ip, data_mpls_tcp_packet.inner_ipv4_hdr.src_addr);
    assert_int_equal(key.dst_ip, data_mpls_tcp_packet.inner_ipv4_hdr.dst_addr);
    assert_int_equal(key.proto, IPPROTO_TCP);
    assert_int_equal(key.src_port, data_mpls_tcp_packet.inner_tcp_hdr.src_port);
    assert_int_equal(key.dst_port, data_mpls_tcp_packet.inner_tcp_hdr.dst_port);

    RTE_SET_USED(state);
}

static void
test_parse_packet_key_from_mpls_l3_tcp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_tcp_l3_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L3.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L3);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L3.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, false);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.src_ip, data_mpls_tcp_l3_packet.inner_ipv4_hdr.src_addr);
    assert_int_equal(key.dst_ip, data_mpls_tcp_l3_packet.inner_ipv4_hdr.dst_addr);
    assert_int_equal(key.proto, IPPROTO_TCP);
    assert_int_equal(key.src_port, data_mpls_tcp_l3_packet.inner_tcp_hdr.src_port);
    assert_int_equal(key.dst_port, data_mpls_tcp_l3_packet.inner_tcp_hdr.dst_port);

    RTE_SET_USED(state);
}

static void
test_parse_packet_metadata_from_mpls_l2_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_udp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L2.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L2);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L2.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, true);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, l2_nh_id, MPLS_OFF_L2.nexthop_id);
    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, ip_addr,
        data_mpls_udp_packet.inner_ipv4_hdr.dst_addr);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_true(metadata.eth_hdr_present);
    assert_memory_equal(
        &metadata.inner_src_mac[0],
        &data_mpls_udp_packet.inner_eth_hdr.s_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
    assert_memory_equal(
        &metadata.inner_dst_mac[0],
        &data_mpls_udp_packet.inner_eth_hdr.d_addr.addr_bytes[0],
        ETHER_ADDR_LEN);

    RTE_SET_USED(state);
}

static void
test_parse_packet_metadata_from_mpls_l3_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_udp_l3_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L3.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L3);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L3.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, false);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_false(metadata.eth_hdr_present);

    RTE_SET_USED(state);
}

#define assert_returned_error(rc, expected) { \
    if ((rc) != (expected)) \
        fail_msg("Incorrect return value. Expected %d '%s', returned %d '%s'", \
            rc, strerror(-(rc)), expected, strerror(-(expected))); \
}

static void
test_parse_packet_returns_notsup_on_l2_encapsulated_icmp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_ipv4_icmp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L2.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L2);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L2.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, true);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, l2_nh_id, MPLS_OFF_L2.nexthop_id);
    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, ip_addr,
        data_mpls_ipv4_icmp_packet.inner_ipv4_hdr.dst_addr);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_notsup_on_l3_encapsulated_icmp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_ipv4_icmp_l3_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L3.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L3);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L3.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, false);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_notsup_on_l2_encapsulated_sctp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_ipv4_sctp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L2.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L2);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L2.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, true);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, l2_nh_id, MPLS_OFF_L2.nexthop_id);
    expect_value(vr_dpdk_n3k_get_key_nh_from_l2_nh, ip_addr,
        data_mpls_ipv4_sctp_packet.inner_ipv4_hdr.dst_addr);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_key_nh_from_l2_nh, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_notsup_on_l3_encapsulated_sctp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_ipv4_sctp_l3_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L3.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L3);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L3.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, false);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_notsup_on_encapsulated_arp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_ipv4_arp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L2.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L2);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L2.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, true);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_notsup_on_l2_encapsulated_ipv6_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_ipv6_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L2.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L2);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L2.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, true);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_notsup_on_l3_encapsulated_ipv6_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_ipv6_l3_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_offload_mpls_get_by_label, label, MPLS_OFF_L3.label);
    will_return(vr_dpdk_n3k_offload_mpls_get_by_label, &MPLS_OFF_L3);

    expect_value(vr_dpdk_n3k_is_nh_l2, nh_id, MPLS_OFF_L3.nexthop_id);
    will_return(vr_dpdk_n3k_is_nh_l2, false);
    will_return(vr_dpdk_n3k_is_nh_l2, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);

    RTE_SET_USED(state);
}

static void
test_parse_packet_returns_notsup_on_more_than_one_label_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_mpls_not_bos_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);

    RTE_SET_USED(state);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {

        cmocka_unit_test(test_parse_packet_key_from_mpls_l2_udp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_key_from_mpls_l3_udp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_key_from_mpls_l2_tcp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_key_from_mpls_l3_tcp_on_fabric_ingress),

        cmocka_unit_test(test_parse_packet_metadata_from_mpls_l2_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_metadata_from_mpls_l3_on_fabric_ingress),

        // /* FABRIC_RX, tunnelled traffic */
        cmocka_unit_test(test_parse_packet_returns_notsup_on_l2_encapsulated_icmp_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_notsup_on_l3_encapsulated_icmp_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_notsup_on_l2_encapsulated_sctp_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_notsup_on_l3_encapsulated_sctp_on_fabric_rx),

        cmocka_unit_test(test_parse_packet_returns_notsup_on_encapsulated_arp_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_notsup_on_l2_encapsulated_ipv6_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_notsup_on_l3_encapsulated_ipv6_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_notsup_on_more_than_one_label_on_fabric_rx),
    };

    return cmocka_run_group_tests_name(GROUP_NAME, tests, NULL, NULL);
}
