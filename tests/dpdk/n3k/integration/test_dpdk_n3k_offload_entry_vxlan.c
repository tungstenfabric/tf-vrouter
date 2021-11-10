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

#include <rte_debug.h>
#include <rte_malloc.h>

#include <vr_dpdk.h>

#include "int_test_utils.h"
#include "int_test_utils_vxlan.h"
#include "../fakes/fake_vr_offloads.h"

#include "vr_dpdk_n3k_packet_parser.h"

#include <offload_entry/vr_dpdk_n3k_offload_entry.h>

#include <cmocka.h>

static int
test_setup(void** state)
{
    int ret = 0;
    ret = mock_vr_dpdk_n3k_offload_interface_init(100);
    assert_int_equal(ret, 0);
    ret = mock_vr_dpdk_n3k_offload_nexthop_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_offload_vxlan_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_offload_flow_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_packet_metadata_init(100);
    assert_int_equal(ret, 0);
    reset_route_table();
    vr_dpdk_n3k_test_reset_mirrors();
    return 0;
}

static int
test_teardown(void** state)
{
    mock_vr_dpdk_n3k_offload_interface_exit();
    mock_vr_dpdk_n3k_offload_nexthop_exit();
    vr_dpdk_n3k_offload_vxlan_exit();
    vr_dpdk_n3k_offload_flow_exit();
    vr_dpdk_n3k_packet_metadata_exit();
    return 0;
}

static void
test_fill_offload_entry_2_vms_with_routing_vxlan(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    struct vr_n3k_ips ip = {
        .type = VR_N3K_IP_TYPE_IPV4,
        .src = {
            .ipv4 = 0x01010101
        },
        .dst = {
            .ipv4 = 0x02020202
        },
    };
    struct vr_n3k_ips reverse_ip = {
        .type = ip.type,
        .src = ip.dst,
        .dst = ip.src
    };
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 1;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t l2_rcv_nh_id = 4;
    uint32_t vrf_id = 1;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, &reverse_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_vxlan(
        src_mac, dst_mac, &ip, proto, src_port, dst_port,
        key_nh_id);

    //key_nh
    entry.src_nh = create_offload_nexthop(key_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, ip.type, ip.src, key_nh_id, 0);

    struct vr_nexthop *l2_rcv_nexthop =
        create_offload_nexthop(l2_rcv_nh_id, NH_L2_RCV, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, l2_rcv_nexthop->nh_id, 1);

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, ip.type, ip.dst, entry.dst_nh->nh_id, 0);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = true;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_vxlan(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_with_vxlan_lookup(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    struct vr_n3k_ips ip = {
        .type = VR_N3K_IP_TYPE_IPV4,
        .src = {
            .ipv4 = 0x01010101
        },
        .dst = {
            .ipv4 = 0x02020202
        },
    };
    struct vr_n3k_ips reverse_ip = {
        .type = ip.type,
        .src = ip.dst,
        .dst = ip.src
    };
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 1;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint32_t vni = 101;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, &reverse_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_vm_rx(
        src_mac, dst_mac, &ip, proto, src_port, dst_port, key_nh_id);

    //key_nh
    create_offload_nexthop(key_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, ip.type, ip.src, key_nh_id, 0);

    entry.src_nh = create_offload_nexthop(src_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, src_mac, entry.src_nh->nh_id, 1);

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_TUNNEL, NH_FLAG_VALID | NH_FLAG_TUNNEL_VXLAN, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, vni);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    create_offload_vxlan(vni, entry.dst_nh->nh_id);

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN;
    entry.tunnel_label = vni;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_vxlan(&test_offload_entry, &entry);
}

static void
test_fill_ipv6_offload_entry_2_vms_with_routing_vxlan(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    struct vr_n3k_ips ip = {
        .type = VR_N3K_IP_TYPE_IPV6,
        .src = {
            .ipv6 = "\xde\xad\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\xb0",
        },
        .dst = {
            .ipv6 = "\xde\xad\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x0b",
        },
    };
    struct vr_n3k_ips reverse_ip = {
        .type = ip.type,
        .src = ip.dst,
        .dst = ip.src
    };
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 1;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t l2_rcv_nh_id = 4;
    uint32_t vrf_id = 1;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, &reverse_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_vxlan(
        src_mac, dst_mac, &ip, proto, src_port, dst_port,
        key_nh_id);

    //key_nh
    entry.src_nh = create_offload_nexthop(key_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, ip.type, ip.src, key_nh_id, 0);

    struct vr_nexthop *l2_rcv_nexthop =
        create_offload_nexthop(l2_rcv_nh_id, NH_L2_RCV, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, l2_rcv_nexthop->nh_id, 1);

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, ip.type, ip.dst, entry.dst_nh->nh_id, 0);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = true;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_vxlan(&test_offload_entry, &entry);
}

static void
test_fill_ipv6_offload_entry_with_vxlan_lookup(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    struct vr_n3k_ips ip = {
        .type = VR_N3K_IP_TYPE_IPV6,
        .src = {
            .ipv6 = "\xde\xad\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\xb0",
        },
        .dst = {
            .ipv6 = "\xde\xad\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x0b",
        },
    };
    struct vr_n3k_ips reverse_ip = {
        .type = ip.type,
        .src = ip.dst,
        .dst = ip.src
    };
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 1;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint32_t vni = 101;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, &reverse_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_vm_rx(
        src_mac, dst_mac, &ip, proto, src_port, dst_port, key_nh_id);

    //key_nh
    create_offload_nexthop(key_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, ip.type, ip.src, key_nh_id, 0);

    entry.src_nh = create_offload_nexthop(src_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, src_mac, entry.src_nh->nh_id, 1);

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_TUNNEL, NH_FLAG_VALID | NH_FLAG_TUNNEL_VXLAN, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, vni);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    create_offload_vxlan(vni, entry.dst_nh->nh_id);

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_VXLAN;
    entry.tunnel_label = vni;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_vxlan(&test_offload_entry, &entry);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_2_vms_with_routing_vxlan,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_with_vxlan_lookup,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_ipv6_offload_entry_2_vms_with_routing_vxlan,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_ipv6_offload_entry_with_vxlan_lookup,
            test_setup,
            test_teardown),
    };

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("FATAL: EAL initialization failed: %s\n", rte_strerror(rte_errno));
        return 1;
    }

    return cmocka_run_group_tests_name(
        "vr_dpdk_n3k_fill_offload_entry_vxlan", tests, NULL, NULL);
}
