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
    vr_dpdk_n3k_offload_flow_exit();
    vr_dpdk_n3k_packet_metadata_exit();
    return 0;
}

static void
test_fill_offload_entry_2_vms_l2(void **state)
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
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;

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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_mirroring_per_flow(void **state)
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
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint8_t mirror_id = 5;
    uint32_t mirror_nexthop_id = 9;
    uint32_t mirror_vif_id = 8;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, mirror_id);
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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    struct vr_nexthop *mirror_nh = create_offload_nexthop(mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID, mirror_vif_id, AF_BRIDGE);
    create_offload_mirror(mirror_id, mirror_nh);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.mirror_vif = create_vif(mirror_vif_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_mirroring_per_interface(void **state)
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
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint8_t mirror_id = 7;
    uint32_t mirror_nexthop_id = 9;
    uint32_t mirror_vif_id = 8;

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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    struct vr_nexthop *mirror_nh = create_offload_nexthop(mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID, mirror_vif_id, AF_BRIDGE);
    create_offload_mirror(mirror_id, mirror_nh);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx,
        VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, mirror_id);
    entry.mirror_vif = create_vif(mirror_vif_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_two_mirrors(void **state)
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
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint8_t flow_mirror_id = 5;
    uint32_t flow_mirror_nexthop_id = 9;
    uint32_t flow_mirror_vif_id = 8;

    // Only one mirroring entry is currently supported and per flow mirroring
    // has higher priority (than per interface mirroring).
    // As a result interface_mirroring_id assigned to destination vif should
    // be ignored if mirroring attached to flow is successfully fetched.
    uint8_t interface_mirror_id = 13;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, flow_mirror_id);
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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    struct vr_nexthop *mirror_nh = create_offload_nexthop(flow_mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID,
        flow_mirror_vif_id, AF_BRIDGE);
    create_offload_mirror(flow_mirror_id, mirror_nh);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx,
        VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx,
        interface_mirror_id);
    entry.mirror_vif = create_vif(flow_mirror_vif_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_mirroring_per_flow_is_broken(void **state)
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
    uint8_t interface_mirror_id = 7;
    uint32_t interface_mirror_nexthop_id = 9;
    uint32_t interface_mirror_vif_id = 8;

    // Flow mirror id is assigned to the flow, but mirroring entry is
    // not available. Interface mirroring is available, but the procedure
    // should return error code when flow mirror can not be fetched.
    uint8_t flow_mirror_id = 19;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, flow_mirror_id);
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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    struct vr_nexthop *mirror_nh = create_offload_nexthop(interface_mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID,
        interface_mirror_vif_id, AF_BRIDGE);
    create_offload_mirror(interface_mirror_id, mirror_nh);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx,
        VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx,
        interface_mirror_id);
    entry.mirror_vif = NULL;

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_not_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_offload_entry_mirroring_per_interface_is_broken(void **state)
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
    uint8_t interface_mirror_id = 7;
    uint32_t interface_mirror_nexthop_id = 9;
    uint32_t interface_mirror_vif_id = 8;

    uint8_t flow_mirror_id = VR_MAX_MIRROR_INDICES;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, flow_mirror_id);
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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    create_offload_nexthop(interface_mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID,
        interface_mirror_vif_id, AF_BRIDGE);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx,
        interface_mirror_id);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx,
        VR_MAX_MIRROR_INDICES);
    entry.mirror_vif = NULL;

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, -ENOENT);
}

static void
test_fill_ipv6_offload_entry_2_vms_l2(void **state)
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
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;

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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.mirror_vif = NULL;
    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_ipv6_offload_entry_mirroring_per_flow(void **state)
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
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint8_t mirror_id = 5;
    uint32_t mirror_nexthop_id = 9;
    uint32_t mirror_vif_id = 8;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, mirror_id);
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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    struct vr_nexthop *mirror_nh = create_offload_nexthop(mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID, mirror_vif_id, AF_BRIDGE);
    create_offload_mirror(mirror_id, mirror_nh);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, VR_MAX_MIRROR_INDICES);
    entry.mirror_vif = create_vif(mirror_vif_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_ipv6_offload_entry_mirroring_per_interface(void **state)
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
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint8_t mirror_id = 7;
    uint32_t mirror_nexthop_id = 9;
    uint32_t mirror_vif_id = 8;

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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    struct vr_nexthop *mirror_nh = create_offload_nexthop(mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID, mirror_vif_id, AF_BRIDGE);
    create_offload_mirror(mirror_id, mirror_nh);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx,
        VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx, mirror_id);
    entry.mirror_vif = create_vif(mirror_vif_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_ipv6_offload_entry_two_mirrors(void **state)
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
    uint8_t proto = 17;
    uint8_t src_mac[] = {0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a};
    uint8_t dst_mac[] = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    uint32_t key_nh_id = 1;
    uint32_t src_nh_id = 2, src_vif_id = 2;
    uint32_t dst_nh_id = 3, dst_vif_id = 3;
    uint32_t vrf_id = 1;
    uint8_t flow_mirror_id = 5;
    uint32_t flow_mirror_nexthop_id = 9;
    uint32_t flow_mirror_vif_id = 8;

    // Only one mirroring entry is currently supported and per flow mirroring
    // has higher priority (than per interface mirroring).
    // As a result interface_mirroring_id assigned to destination vif should
    // be ignored if mirroring attached to flow is successfully fetched.
    uint8_t interface_mirror_id = 13;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, flow_mirror_id);
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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    struct vr_nexthop *mirror_nh = create_offload_nexthop(flow_mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID,
        flow_mirror_vif_id, AF_BRIDGE);
    create_offload_mirror(flow_mirror_id, mirror_nh);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx,
        VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx,
        interface_mirror_id);
    entry.mirror_vif = create_vif(flow_mirror_vif_id, VR_MAX_MIRROR_INDICES);

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_ipv6_offload_entry_mirroring_per_flow_is_broken(void **state)
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
    uint8_t interface_mirror_id = 7;
    uint32_t interface_mirror_nexthop_id = 9;
    uint32_t interface_mirror_vif_id = 8;

    // Flow mirror id is assigned to the flow, but mirroring entry is
    // not available. Interface mirroring is available, but the procedure
    // should return error code when flow mirror can not be fetched.
    uint8_t flow_mirror_id = 19;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, flow_mirror_id);
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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    struct vr_nexthop *mirror_nh = create_offload_nexthop(interface_mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID,
        interface_mirror_vif_id, AF_BRIDGE);
    create_offload_mirror(interface_mirror_id, mirror_nh);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx,
        VR_MAX_MIRROR_INDICES);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx,
        interface_mirror_id);
    entry.mirror_vif = NULL;

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_not_equal(ret, 0);
    check_offload_entry(&test_offload_entry, &entry);
}

static void
test_fill_ipv6_offload_entry_mirroring_per_interface_is_broken(void **state)
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
    uint8_t interface_mirror_id = 7;
    uint32_t interface_mirror_nexthop_id = 9;
    uint32_t interface_mirror_vif_id = 8;

    uint8_t flow_mirror_id = VR_MAX_MIRROR_INDICES;

    entry.flow = create_offload_flow(
        flow_id, reverse_flow_id, &ip, proto,
        src_port, dst_port, key_nh_id, vrf_id, flow_mirror_id);
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

    entry.dst_nh = create_offload_nexthop(dst_nh_id, NH_ENCAP, NH_FLAG_VALID, dst_vif_id, AF_BRIDGE);
    add_nh_to_bridge_table(vrf_id, dst_mac, entry.dst_nh->nh_id, 1);

    create_offload_nexthop(interface_mirror_nexthop_id, NH_ENCAP, NH_FLAG_VALID,
        interface_mirror_vif_id, AF_BRIDGE);

    entry.src_vif = create_vif(entry.src_nh->nh_dev->vif_idx,
        interface_mirror_id);
    entry.dst_vif = create_vif(entry.dst_nh->nh_dev->vif_idx,
        VR_MAX_MIRROR_INDICES);
    entry.mirror_vif = NULL;

    entry.route_traffic = false;

    entry.tunnel_type = VR_N3K_OFFLOAD_TUNNEL_NONE;
    entry.tunnel_label = 0;

    struct vr_n3k_offload_entry test_offload_entry = {0};
    int ret = vr_dpdk_n3k_fill_offload_entry(entry.flow, &test_offload_entry);
    assert_int_equal(ret, -ENOENT);
}


int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_2_vms_l2,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_mirroring_per_flow,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_mirroring_per_interface,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_two_mirrors,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_mirroring_per_flow_is_broken,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_offload_entry_mirroring_per_interface_is_broken,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_ipv6_offload_entry_2_vms_l2,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_ipv6_offload_entry_mirroring_per_flow,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_ipv6_offload_entry_mirroring_per_interface,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_ipv6_offload_entry_two_mirrors,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_ipv6_offload_entry_mirroring_per_flow_is_broken,
            test_setup,
            test_teardown),
        cmocka_unit_test_setup_teardown(
            test_fill_ipv6_offload_entry_mirroring_per_interface_is_broken,
            test_setup,
            test_teardown),
    };

    int ret = rte_eal_init(argc, argv);
    if (ret < 0) {
        rte_panic("FATAL: EAL initialization failed: %s\n", rte_strerror(rte_errno));
        return 1;
    }

    return cmocka_run_group_tests_name(
        "vr_dpdk_n3k_fill_offload_entry_agnostic", tests, NULL, NULL);
}
