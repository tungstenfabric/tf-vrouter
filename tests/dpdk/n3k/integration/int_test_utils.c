/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "int_test_utils.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <rte_debug.h>
#include <rte_malloc.h>

#include <vr_nexthop.h>
#include <vr_interface.h>
#include <vr_dpdk.h>

#include "vr_dpdk_n3k_nexthop.h"
#include "vr_dpdk_n3k_vxlan.h"
#include "vr_dpdk_n3k_packet_parser.h"
#include "vr_dpdk_n3k_routes.h"
#include <offload_entry/vr_dpdk_n3k_offload_entry.h>

#include <cmocka.h>

struct vr_n3k_offload_flow *
create_offload_flow(
    uint32_t id,
    uint32_t reverse_id,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_pot,
    uint32_t nh_id,
    uint16_t src_vrf_id,
    uint8_t mirror_id
)
{
    struct vr_n3k_offload_flowtable_key flow_key = {0};
    flow_key.fe_index = id;

    struct vr_n3k_offload_flow *n3k_flow = rte_zmalloc("n3k_flow", sizeof(*n3k_flow), 0);
    assert_non_null(n3k_flow);
    n3k_flow->id = id;
    n3k_flow->reverse_id = reverse_id;
    n3k_flow->action = 0;
    n3k_flow->src_ip = src_ip;
    n3k_flow->dst_ip = dst_ip;
    n3k_flow->proto = proto;
    n3k_flow->src_port = src_port;
    n3k_flow->dst_port = dst_pot;
    n3k_flow->tunnel_udp_src_port = 1000;
    n3k_flow->nh_id = nh_id;
    n3k_flow->src_vrf_id = src_vrf_id;
    n3k_flow->mirror_id = mirror_id;
    vr_dpdk_n3k_offload_flow_table_add(&flow_key, n3k_flow);
    return n3k_flow;
}

struct vr_dpdk_n3k_packet_key
create_packet_key(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t nh_id
)
{
    struct vr_dpdk_n3k_packet_key packet_key = {0};
    packet_key.nh_id = nh_id;
    packet_key.src_ip = src_ip;
    packet_key.dst_ip = dst_ip;
    packet_key.proto = proto;
    packet_key.src_port = src_port;
    packet_key.dst_port = dst_port;
    return packet_key;
}

struct vr_dpdk_n3k_packet_metadata
create_packet_metadata_for_vm_rx(
    uint8_t* src_mac,
    uint8_t* dst_mac,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t nh_id
)
{
    struct vr_dpdk_n3k_packet_key packet_key =
        create_packet_key(src_ip, dst_ip, proto, src_port, dst_port, nh_id);
    struct vr_dpdk_n3k_packet_metadata packet_metadata;
    packet_metadata.eth_hdr_present = true;
    memcpy(packet_metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(packet_metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);
    int ret = vr_dpdk_n3k_packet_metadata_insert_copy(
        &packet_key, &packet_metadata);
    assert_int_equal(ret, 0);
    return packet_metadata;
}

struct vr_n3k_offload_nexthop *
create_offload_nexthop(
    uint32_t nh_id,
    uint8_t type,
    uint32_t flags,
    uint16_t interface_id,
    uint8_t family
)
{
    return create_offload_nexthop_composite(
            nh_id, type, flags, interface_id, family, 0, NULL);
}

struct vr_n3k_offload_nexthop *
create_offload_nexthop_composite(
    uint32_t nh_id,
    uint8_t type,
    uint32_t flags,
    uint16_t interface_id,
    uint8_t family,
    uint16_t component_cnt,
    struct vr_n3k_offload_nh_label * component_nhs
)
{
    struct vr_n3k_offload_nexthop *nh
        = rte_zmalloc("nh", sizeof(*nh), 0);
    assert_non_null(nh);
    nh->id = nh_id;
    nh->interface_id = interface_id;
    nh->nh_family = family;
    nh->type = type;
    nh->nh_flags = flags;

    if (component_cnt != 0) {
        nh->cnh_cnt = component_cnt;
        nh->component_nhs = rte_zmalloc(
            "n3k_offload_nh_cmp",
            component_cnt * sizeof(struct vr_n3k_offload_nh_label),
            sizeof(struct vr_n3k_offload_nh_label)
        );
        assert_non_null(nh->component_nhs);
        rte_memcpy(nh->component_nhs, component_nhs, component_cnt * sizeof(*component_nhs));
    }

    vr_dpdk_n3k_offload_nexthop_insert(nh);

    return nh;
}

void
add_nh_to_bridge_table(
    uint32_t vrf_id,
    uint8_t *mac,
    uint32_t nh_id,
    uint32_t label
)
{
    struct vr_n3k_offload_bridge_key bridge_key = { { 0 } };
    bridge_key.vrf_id = vrf_id;
    memcpy(bridge_key.mac, mac, VR_ETHER_ALEN);

    struct vr_n3k_offload_bridge_value bridge_value;
    bridge_value.nh_id = nh_id;
    bridge_value.label = label;
    vr_dpdk_n3k_offload_bridge_add_internal(&bridge_key, &bridge_value);
}

void
add_nh_to_route_table(
    uint32_t vrf_id,
    uint32_t ip,
    uint32_t nh_id,
    uint32_t label
)
{
    struct vr_n3k_offload_route_value route_value;
    route_value.nh_id = nh_id;
    route_value.label = label;
    vr_dpdk_n3k_offload_route_add_internal(vrf_id, ip, 32, &route_value);
}

struct vr_n3k_offload_interface*
create_vif(uint16_t interface_id, uint8_t mirror_id)
{
    struct vr_n3k_offload_interface *vif
        = rte_zmalloc("vif", sizeof(*vif), 0);
    assert_non_null(vif);
    vif->id = interface_id;
    vif->mirror_id = mirror_id;
    vr_dpdk_n3k_offload_interface_insert(vif);
    return vif;
}

void
check_packet_metadata(
    struct vr_dpdk_n3k_packet_metadata *test_metadata,
    struct vr_dpdk_n3k_packet_metadata *good_metadata
)
{
    assert_true(test_metadata->eth_hdr_present == good_metadata->eth_hdr_present);

    assert_true(memcmp(test_metadata->inner_src_mac,
        good_metadata->inner_src_mac, VR_ETHER_ALEN) == 0);
    assert_true(memcmp(test_metadata->inner_dst_mac,
        good_metadata->inner_dst_mac, VR_ETHER_ALEN) == 0);
}

void
check_offload_entry(
    struct vr_n3k_offload_entry *test_entry,
    struct vr_n3k_offload_entry *good_entry
)
{
    assert_ptr_equal(test_entry->src_nh, good_entry->src_nh);
    assert_ptr_equal(test_entry->dst_nh, good_entry->dst_nh);
    assert_ptr_equal(test_entry->src_vif, good_entry->src_vif);
    assert_ptr_equal(test_entry->dst_vif, good_entry->dst_vif);
    assert_ptr_equal(test_entry->flow, good_entry->flow);
    assert_ptr_equal(test_entry->reverse_flow, good_entry->reverse_flow);
    assert_ptr_equal(test_entry->mirror_vif, good_entry->mirror_vif);
    assert_true(test_entry->route_traffic == good_entry->route_traffic);
    check_packet_metadata(&test_entry->pkt_metadata, &good_entry->pkt_metadata);
}

struct vr_n3k_offload_mirror*
create_offload_mirror(uint32_t id, uint32_t nexthop_id)
{
    struct vr_n3k_offload_mirror *offload_mirror
        = rte_zmalloc("n3k_offload_mirror", sizeof(*offload_mirror), 0);
    assert_non_null(offload_mirror);
    offload_mirror->id = id;
    offload_mirror->nexthop_id = nexthop_id;
    vr_dpdk_n3k_offload_mirror_insert(offload_mirror);

    return offload_mirror;
}
