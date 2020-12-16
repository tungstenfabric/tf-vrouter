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
#include "int_test_utils_mplsoudp.h"

#include "vr_dpdk_n3k_packet_parser.h"
#include "vr_dpdk_n3k_routes.h"

#include <offload_entry/vr_dpdk_n3k_offload_entry.h>

#include <cmocka.h>

static int
test_setup(void** state)
{
    int ret = 0;
    ret = vr_dpdk_n3k_offload_interface_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_offload_nexthop_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_offload_mpls_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_offload_flow_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_offload_mirror_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_packet_metadata_init(100);
    assert_int_equal(ret, 0);
    ret = vr_dpdk_n3k_offload_routing_init(100, 100);
    assert_int_equal(ret, 0);
    return 0;
}

static int
test_teardown(void** state)
{
    vr_dpdk_n3k_offload_interface_exit();
    vr_dpdk_n3k_offload_nexthop_exit();
    vr_dpdk_n3k_offload_mpls_exit();
    vr_dpdk_n3k_offload_flow_exit();
    vr_dpdk_n3k_offload_mirror_exit();
    vr_dpdk_n3k_packet_metadata_exit();
    vr_dpdk_n3k_offload_routing_exit();
    return 0;
}

static void
test_fill_offload_entry_l2_mplsoudp_egress(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    uint32_t src_ip = 0x01010101;
    uint32_t dst_ip = 0x02020202;
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint32_t label = 101;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, src_ip, dst_ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, dst_ip, src_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_vm_rx(
        src_mac, dst_mac, src_ip, dst_ip, proto, src_port, dst_port, key_nh_id);

    //key_nh
    create_offload_nexthop(key_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, src_ip, key_nh_id, 0);

    entry.src_nh = create_offload_nexthop(src_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, src_mac, entry.src_nh->id, 1);

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_TUNNEL, NH_FLAG_VALID | NH_FLAG_TUNNEL_UDP_MPLS, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->id, label);

    entry.src_vif = create_vif(entry.src_nh->interface_id, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->interface_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLS;
    entry.tunnel_label = label;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_mplsoudp(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_l2_mplsoudp_egress_cnh(void **state)
{
    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    uint32_t src_ip = 0x01010101;
    uint32_t dst_ip = 0x02020202;
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t dst_cnh_a_id = 4;
    uint32_t dst_cnh_b_id = 5;
    uint32_t vrf_id = 1;
    uint32_t label_a = 101;
    uint32_t label_b = 102;

    struct vr_n3k_offload_entry entry;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, src_ip, dst_ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.flow->ecmp_nh_idx = 1;
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, dst_ip, src_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_vm_rx(
        src_mac, dst_mac, src_ip, dst_ip, proto, src_port, dst_port, key_nh_id);

    //key_nh
    create_offload_nexthop(
        key_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, src_ip, key_nh_id, 0);

    entry.src_nh = create_offload_nexthop(
        src_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, src_mac, entry.src_nh->id, 1);

    // Given composite nexthop consisting of two nexthops ("a" & "b") with different labels.
    create_offload_nexthop(
        dst_cnh_a_id,
        NH_TUNNEL,
        NH_FLAG_VALID | NH_FLAG_TUNNEL_UDP_MPLS,
        dst_vif_id,
        AF_BRIDGE
    );
    // Note: Marking the "b" nexthop as expected (by assigning to
    // entry.dst_nh), as we've set ecmp_nh_idx to 1.
    entry.dst_nh = create_offload_nexthop(
        dst_cnh_b_id,
        NH_TUNNEL,
        NH_FLAG_VALID | NH_FLAG_TUNNEL_UDP_MPLS,
        dst_vif_id,
        AF_BRIDGE
    );
    struct vr_n3k_offload_nh_label dst_cnhs[2] = {
        { .nh_idx = dst_cnh_a_id, .label = label_a },
        { .nh_idx = dst_cnh_b_id, .label = label_b },
    };
    create_offload_nexthop_composite(
        dst_nh_id, NH_COMPOSITE, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE, 2, dst_cnhs);
    add_nh_to_bridge_table(vrf_id, dst_mac, dst_nh_id, -1);

    entry.src_vif = create_vif(entry.src_nh->interface_id, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->interface_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLS;
    entry.tunnel_label = label_b;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_mplsoudp(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_l2_mplsoudp_ingress(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    uint32_t src_ip = 0x01010101;
    uint32_t dst_ip = 0x02020202;
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint32_t label = 101;
    bool inner_l2_hdr_present = true;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, src_ip, dst_ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, dst_ip, src_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_mplsoudp(
        src_mac, dst_mac, src_ip, dst_ip, proto, src_port, dst_port,
        key_nh_id, inner_l2_hdr_present);

    //key_nh
    create_offload_nexthop(key_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, dst_ip, key_nh_id, 0);

    entry.src_nh = create_offload_nexthop(src_nh_id, NH_TUNNEL, NH_FLAG_VALID | NH_FLAG_TUNNEL_UDP_MPLS, src_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, src_mac, entry.src_nh->id, 2);

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->id, label);

    create_offload_mpls(label, dst_nh_id);

    entry.src_vif = create_vif(src_vif_id, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(dst_vif_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLS;
    entry.tunnel_label = label;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_mplsoudp(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_l3_mplsoudp_egress(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    uint32_t src_ip = 0x01010101;
    uint32_t dst_ip = 0x02020202;
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 17;
    uint8_t vrouter_mac[] = {0x00, 0x00, 0x5e, 0x00, 0x01, 0x00};
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t l2_rcv_nh_id = 4;
    uint32_t vrf_id = 1;
    uint32_t label = 101;

    entry.flow = create_offload_flow(
	flow_id, reverse_flow_id, src_ip, dst_ip, proto,
	src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.reverse_flow = create_offload_flow(
	reverse_flow_id, flow_id, dst_ip, src_ip, proto,
	dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_vm_rx(
	src_mac, vrouter_mac, src_ip, dst_ip, proto, src_port, dst_port, key_nh_id);

    entry.src_nh = create_offload_nexthop(src_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, src_ip, entry.src_nh->id, 1);

    struct vr_n3k_offload_nexthop *l2_rcv_nexthop =
	create_offload_nexthop(l2_rcv_nh_id, NH_L2_RCV, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, vrouter_mac, l2_rcv_nexthop->id, 1);

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_TUNNEL, NH_FLAG_VALID | NH_FLAG_TUNNEL_UDP_MPLS, dst_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, dst_ip, entry.dst_nh->id, label);

    entry.src_vif = create_vif(entry.src_nh->interface_id, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->interface_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = true;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLS;
    entry.tunnel_label = label;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_mplsoudp(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_l3_mplsoudp_egress_cnh(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    uint32_t src_ip = 0x01010101;
    uint32_t dst_ip = 0x02020202;
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 17;
    uint8_t vrouter_mac[] = {0x00, 0x00, 0x5e, 0x00, 0x01, 0x00};
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t dst_cnh_a_id = 34;
    uint32_t dst_cnh_b_id = 35;
    uint32_t l2_rcv_nh_id = 4;
    uint32_t vrf_id = 1;
    uint32_t label_a = 101;
    uint32_t label_b = 102;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, src_ip, dst_ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.flow->ecmp_nh_idx = 1;
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, dst_ip, src_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_vm_rx(
	src_mac, vrouter_mac, src_ip, dst_ip, proto, src_port, dst_port, key_nh_id);

    entry.src_nh = create_offload_nexthop(src_nh_id, NH_ENCAP, NH_FLAG_VALID, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, src_ip, entry.src_nh->id, 1);

    struct vr_n3k_offload_nexthop *l2_rcv_nexthop =
	create_offload_nexthop(l2_rcv_nh_id, NH_L2_RCV, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, vrouter_mac, l2_rcv_nexthop->id, 1);

    // Given composite nexthop consisting of two nexthops ("a" & "b") with different labels.
    create_offload_nexthop(
        dst_cnh_a_id,
        NH_TUNNEL,
        NH_FLAG_VALID | NH_FLAG_TUNNEL_UDP_MPLS,
        dst_vif_id,
        AF_INET
    );
    // Note: Marking the "b" nexthop as expected (by assigning to
    // entry.dst_nh), as we've set ecmp_nh_idx to 1.
    entry.dst_nh = create_offload_nexthop(
        dst_cnh_b_id,
        NH_TUNNEL,
        NH_FLAG_VALID | NH_FLAG_TUNNEL_UDP_MPLS,
        dst_vif_id,
        AF_INET
    );
    struct vr_n3k_offload_nh_label dst_cnhs[2] = {
        { .nh_idx = dst_cnh_a_id, .label = label_a },
        { .nh_idx = dst_cnh_b_id, .label = label_b },
    };
    create_offload_nexthop_composite(
            dst_nh_id, NH_COMPOSITE, NH_FLAG_VALID, dst_vif_id, AF_INET, 2, dst_cnhs);
    add_nh_to_route_table(vrf_id, dst_ip, dst_nh_id, 0);

    entry.src_vif = create_vif(entry.src_nh->interface_id, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->interface_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = true;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLS;
    entry.tunnel_label = label_b;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_mplsoudp(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_l3_mplsoudp_ingress(void **state)
{
    struct vr_n3k_offload_entry entry;

    uint32_t flow_id = 1;
    uint32_t reverse_flow_id = 2;
    uint32_t src_ip = 0x01010101;
    uint32_t dst_ip = 0x02020202;
    uint16_t src_port = 10;
    uint16_t dst_port = 20;
    uint8_t proto = 17;
    uint8_t empty_mac[] = {};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint32_t label = 101;
    bool inner_l2_hdr_present = false;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, src_ip, dst_ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);
    entry.reverse_flow = create_offload_flow(
        reverse_flow_id, flow_id, dst_ip, src_ip, proto,
        dst_port, src_port, key_nh_id, vrf_id, VR_MAX_MIRROR_INDICES);

    entry.pkt_metadata = create_packet_metadata_for_mplsoudp(
        empty_mac, empty_mac, src_ip, dst_ip, proto, src_port, dst_port,
        key_nh_id, inner_l2_hdr_present);

    //key_nh
    create_offload_nexthop(key_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, dst_ip, key_nh_id, 0);

    entry.src_nh = create_offload_nexthop(src_nh_id, NH_TUNNEL, NH_FLAG_VALID | NH_FLAG_TUNNEL_UDP_MPLS, src_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, src_ip, entry.src_nh->id, 0);

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_INET);
    add_nh_to_route_table(vrf_id, dst_ip, entry.dst_nh->id, label);

    create_offload_mpls(label, dst_nh_id);

    entry.src_vif = create_vif(src_vif_id, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(dst_vif_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = true;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_MPLS;
    entry.tunnel_label = label;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry_mplsoudp(&test_offload_entry, &entry);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_l2_mplsoudp_ingress,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_l2_mplsoudp_egress,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_l2_mplsoudp_egress_cnh,
            test_setup,
            test_teardown),
	cmocka_unit_test_setup_teardown(
	    test_fill_offload_entry_l3_mplsoudp_ingress,
	    test_setup,
	    test_teardown),
	cmocka_unit_test_setup_teardown(
	    test_fill_offload_entry_l3_mplsoudp_egress,
	    test_setup,
	    test_teardown),
	cmocka_unit_test_setup_teardown(
	    test_fill_offload_entry_l3_mplsoudp_egress_cnh,
	    test_setup,
	    test_teardown),
    };

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("FATAL: EAL initialization failed: %s\n", rte_strerror(rte_errno));
        return 1;
    }

    return cmocka_run_group_tests_name(
        "vr_dpdk_n3k_fill_offload_entry_mplsoudp", tests, NULL, NULL);
}
