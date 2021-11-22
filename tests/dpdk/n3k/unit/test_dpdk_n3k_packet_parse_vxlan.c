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

#include <errno.h>
#include <netinet/ether.h>
#include <netinet/in.h>

#include <rte_common.h>

#include <vr_interface.h>
#include <vr_nexthop.h>
#include <vr_os.h>
#include <vr_packet.h>

#include <vr_dpdk_n3k_packet_metadata.h>
#include <vr_dpdk_n3k_packet_parser.h>

#include "test_dpdk_n3k_packet_parse_vxlan.h"

#include <cmocka.h>

#define GROUP_NAME "vr_dpdk_n3k_packet_parse_vxlan"

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

int
vr_dpdk_n3k_get_nh_from_vni_ipv4(const uint32_t vni,
        const rte_be32_t ip_addr, rte_le32_t *out_nh_id)
{
    check_expected(vni);
    check_expected(ip_addr);
    assert_non_null(out_nh_id);
    *out_nh_id = (int)mock();
    return (int)mock();
}

int
vr_dpdk_n3k_get_nh_from_vni_ipv6(const uint32_t vni,
        const uint8_t* ip_addr, rte_le32_t *out_nh_id)
{
    check_expected(vni);
    check_expected(ip_addr);
    assert_non_null(out_nh_id);
    *out_nh_id = (int)mock();
    return (int)mock();
}

static void
test_parse_packet_key_from_udp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_udp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv4, vni, 100);
    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv4, ip_addr, RTE_IPV4(10, 0, 0, 1));
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv4, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv4, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.ip.type, VR_N3K_IP_TYPE_IPV4);
    assert_int_equal(key.ip.src.ipv4, RTE_IPV4(10, 0, 0, 2));
    assert_int_equal(key.ip.dst.ipv4, RTE_IPV4(10, 0, 0, 1));
    assert_int_equal(key.proto, IPPROTO_UDP);
    assert_int_equal(key.src_port, rte_cpu_to_be_16(20000));
    assert_int_equal(key.dst_port, rte_cpu_to_be_16(10000));
}

static void
test_parse_packet_metadata_from_udp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_udp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv4, vni, 100);
    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv4, ip_addr, RTE_IPV4(10, 0, 0, 1));
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv4, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv4, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_true(metadata.eth_hdr_present);
    assert_memory_equal(
        metadata.inner_src_mac,
        &data_vxlan_udp_packet.inner_eth_hdr.s_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
    assert_memory_equal(
        metadata.inner_dst_mac,
        &data_vxlan_udp_packet.inner_eth_hdr.d_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
}

static void
test_parse_packet_key_from_tcp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_tcp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv4, vni, 100);
    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv4, ip_addr, RTE_IPV4(10, 0, 0, 1));
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv4, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv4, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.ip.type, VR_N3K_IP_TYPE_IPV4);
    assert_int_equal(key.ip.src.ipv4, RTE_IPV4(10, 0, 0, 2));
    assert_int_equal(key.ip.dst.ipv4, RTE_IPV4(10, 0, 0, 1));
    assert_int_equal(key.proto, IPPROTO_TCP);
    assert_int_equal(key.src_port, rte_cpu_to_be_16(20000));
    assert_int_equal(key.dst_port, rte_cpu_to_be_16(10000));
}

static void
test_parse_packet_metadata_from_tcp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_tcp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv4, vni, 100);
    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv4, ip_addr, RTE_IPV4(10, 0, 0, 1));
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv4, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv4, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_true(metadata.eth_hdr_present);
    assert_memory_equal(
        metadata.inner_src_mac,
        &data_vxlan_tcp_packet.inner_eth_hdr.s_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
    assert_memory_equal(
        metadata.inner_dst_mac,
        &data_vxlan_tcp_packet.inner_eth_hdr.d_addr.addr_bytes[0],
        ETHER_ADDR_LEN);
}

#define assert_returned_error(rc, expected) { \
    if ((rc) != (expected)) \
        fail_msg("Incorrect return value. Expected %d '%s', returned %d '%s'", \
            rc, strerror(-(rc)), expected, strerror(-(expected))); \
}

static void
test_parse_packet_returns_notsup_on_encapsulated_icmp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_ipv4_icmp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);
}

static void
test_parse_packet_returns_notsup_on_encapsulated_sctp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_ipv4_sctp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);
}

static void
test_parse_packet_returns_notsup_on_encapsulated_arp_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_ether_arp_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);
}

static void
test_parse_packet_ipv6_key_from_udp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_udp_packet_ipv6,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv6, vni, 100);
    expect_memory(
        vr_dpdk_n3k_get_nh_from_vni_ipv6,
        ip_addr,
        data_vxlan_udp_packet_ipv6.inner_ipv6_hdr.dst_addr,
        VR_IP6_ADDRESS_LEN);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv6, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv6, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.ip.type, VR_N3K_IP_TYPE_IPV6);
    assert_memory_equal(key.ip.src.ipv6,
                        data_vxlan_udp_packet_ipv6.inner_ipv6_hdr.src_addr,
                        VR_IP6_ADDRESS_LEN);
    assert_memory_equal(key.ip.dst.ipv6,
                        data_vxlan_udp_packet_ipv6.inner_ipv6_hdr.dst_addr,
                        VR_IP6_ADDRESS_LEN);
    assert_int_equal(key.proto, IPPROTO_UDP);
    assert_int_equal(key.src_port, rte_cpu_to_be_16(20000));
    assert_int_equal(key.dst_port, rte_cpu_to_be_16(10000));
}

static void
test_parse_packet_ipv6_metadata_from_udp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_udp_packet_ipv6,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv6, vni, 100);
    expect_memory(
        vr_dpdk_n3k_get_nh_from_vni_ipv6,
        ip_addr,
        data_vxlan_udp_packet_ipv6.inner_ipv6_hdr.dst_addr,
        VR_IP6_ADDRESS_LEN);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv6, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv6, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_true(metadata.eth_hdr_present);
    assert_memory_equal(
        metadata.inner_src_mac,
        data_vxlan_udp_packet_ipv6.inner_eth_hdr.s_addr.addr_bytes,
        ETHER_ADDR_LEN);
    assert_memory_equal(
        metadata.inner_dst_mac,
        data_vxlan_udp_packet_ipv6.inner_eth_hdr.d_addr.addr_bytes,
        ETHER_ADDR_LEN);
}

static void
test_parse_packet_ipv6_key_from_tcp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_tcp_packet_ipv6,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv6, vni, 100);
    expect_memory(
        vr_dpdk_n3k_get_nh_from_vni_ipv6,
        ip_addr,
        data_vxlan_tcp_packet_ipv6.inner_ipv6_hdr.dst_addr,
        VR_IP6_ADDRESS_LEN);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv6, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv6, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_int_equal(key.nh_id, VIRTUAL_1_VIF.vif_nh_id);
    assert_int_equal(key.ip.type, VR_N3K_IP_TYPE_IPV6);
    assert_memory_equal(key.ip.src.ipv6,
                        data_vxlan_tcp_packet_ipv6.inner_ipv6_hdr.src_addr,
                        VR_IP6_ADDRESS_LEN);
    assert_memory_equal(key.ip.dst.ipv6,
                        data_vxlan_tcp_packet_ipv6.inner_ipv6_hdr.dst_addr,
                        VR_IP6_ADDRESS_LEN);
    assert_int_equal(key.proto, IPPROTO_TCP);
    assert_int_equal(key.src_port, rte_cpu_to_be_16(20000));
    assert_int_equal(key.dst_port, rte_cpu_to_be_16(10000));
}

static void
test_parse_packet_ipv6_metadata_from_tcp_on_fabric_ingress(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_tcp_packet_ipv6,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    expect_value(vr_dpdk_n3k_get_nh_from_vni_ipv6, vni, 100);
    expect_memory(
        vr_dpdk_n3k_get_nh_from_vni_ipv6,
        ip_addr,
        data_vxlan_tcp_packet_ipv6.inner_ipv6_hdr.dst_addr,
        VR_IP6_ADDRESS_LEN);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv6, VIRTUAL_1_VIF.vif_nh_id);
    will_return(vr_dpdk_n3k_get_nh_from_vni_ipv6, 0);

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_int_equal(ret, 0);

    assert_true(metadata.eth_hdr_present);
    assert_memory_equal(
        metadata.inner_src_mac,
        data_vxlan_tcp_packet_ipv6.inner_eth_hdr.s_addr.addr_bytes,
        ETHER_ADDR_LEN);
    assert_memory_equal(
        metadata.inner_dst_mac,
        data_vxlan_tcp_packet_ipv6.inner_eth_hdr.d_addr.addr_bytes,
        ETHER_ADDR_LEN);
}

static void
test_parse_packet_ipv6_returns_notsup_on_encapsulated_icmpv6_on_fabric_rx(void **state)
{
    struct vr_packet pkt = {
        .vp_if = &PHYSICAL_VIF,
        .vp_nh = &test_nexthops[PHYSICAL_VIF.vif_nh_id],
        .vp_head = (uint8_t *)&data_vxlan_ipv6_icmpv6_packet,
        .vp_data = 0,
    };

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;

    int ret = vr_dpdk_n3k_parse_packet(&pkt, &key, &metadata);

    assert_returned_error(ret, -ENOTSUP);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_packet_key_from_udp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_metadata_from_udp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_key_from_tcp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_metadata_from_tcp_on_fabric_ingress),

        /* FABRIC_RX, tunnelled traffic */
        cmocka_unit_test(test_parse_packet_returns_notsup_on_encapsulated_icmp_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_notsup_on_encapsulated_sctp_on_fabric_rx),
        cmocka_unit_test(test_parse_packet_returns_notsup_on_encapsulated_arp_on_fabric_rx),

        /* IPv6 */
        cmocka_unit_test(test_parse_packet_ipv6_key_from_udp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_ipv6_metadata_from_udp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_ipv6_key_from_tcp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_ipv6_metadata_from_tcp_on_fabric_ingress),
        cmocka_unit_test(test_parse_packet_ipv6_returns_notsup_on_encapsulated_icmpv6_on_fabric_rx),
    };

    return cmocka_run_group_tests_name(GROUP_NAME, tests, NULL, NULL);
}
