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
#include <vr_mirror.h>
#include <vr_dpdk.h>

#include "vr_dpdk_n3k_nexthop.h"
#include "vr_dpdk_n3k_vxlan.h"
#include "vr_dpdk_n3k_packet_parser.h"
#include <offload_entry/vr_dpdk_n3k_offload_entry.h>
#include "../fakes/fake_vr_offloads.h"

#include <cmocka.h>

struct vr_n3k_offload_flow *
create_offload_flow(
    uint32_t id,
    uint32_t reverse_id,
    const struct vr_n3k_ips *ip,
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
    n3k_flow->ip = *ip;
    n3k_flow->proto = proto;
    n3k_flow->src_port = src_port;
    n3k_flow->dst_port = dst_pot;
    n3k_flow->tunnel_udp_src_port = 1000;
    n3k_flow->nh_id = nh_id;
    n3k_flow->src_vrf_id = src_vrf_id;
    n3k_flow->mirror_id = mirror_id;
    vr_dpdk_n3k_offload_flow_table_add_unlocked(&flow_key, n3k_flow);
    return n3k_flow;
}

struct vr_dpdk_n3k_packet_key
create_packet_key(
    const struct vr_n3k_ips *ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t nh_id
)
{
    struct vr_dpdk_n3k_packet_key packet_key = {0};
    packet_key.nh_id = nh_id;
    packet_key.ip = *ip;
    packet_key.proto = proto;
    packet_key.src_port = src_port;
    packet_key.dst_port = dst_port;
    return packet_key;
}

struct vr_dpdk_n3k_packet_metadata
create_packet_metadata_for_vm_rx(
    uint8_t* src_mac,
    uint8_t* dst_mac,
    struct vr_n3k_ips *ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t nh_id
)
{
    struct vr_dpdk_n3k_packet_key packet_key =
        create_packet_key(ip, proto, src_port, dst_port, nh_id);
    struct vr_dpdk_n3k_packet_metadata packet_metadata;
    packet_metadata.eth_hdr_present = true;
    memcpy(packet_metadata.inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(packet_metadata.inner_dst_mac, dst_mac, VR_ETHER_ALEN);
    int ret = vr_dpdk_n3k_packet_metadata_insert_copy(
        &packet_key, &packet_metadata, true);
    assert_int_equal(ret, 0);
    return packet_metadata;
}

struct vr_nexthop *
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

struct vr_nexthop *
create_offload_nexthop_composite(
    uint32_t nh_id,
    uint8_t type,
    uint32_t flags,
    uint16_t interface_id,
    uint8_t family,
    uint16_t component_cnt,
    struct vr_component_nh * component_nhs
)
{
    struct vr_nexthop *nh
        = rte_zmalloc("nh", sizeof(*nh), 0);
    assert_non_null(nh);
    nh->nh_id = nh_id;
    nh->nh_family = family;
    nh->nh_type = type;
    nh->nh_flags = flags;
    nh->nh_dev = rte_zmalloc("vr_interface", sizeof(*nh->nh_dev), 0);
    assert_non_null(nh->nh_dev);

    nh->nh_dev->vif_idx = interface_id;

    if (component_cnt != 0) {
        nh->nh_u.nh_composite.cnt = component_cnt;
        nh->nh_u.nh_composite.component = rte_zmalloc(
            "n3k_offload_nh_cmp",
            component_cnt * sizeof(struct vr_component_nh),
            sizeof(struct vr_component_nh)
        );
        assert_non_null(nh->nh_u.nh_composite.component);
        rte_memcpy(nh->nh_u.nh_composite.component, component_nhs, component_cnt * sizeof(*component_nhs));
    }

    mock_vr_dpdk_n3k_offload_nexthop_insert(nh);

    return nh;
}

#define MAX_BRIDGES 16

struct bridge {
    uint32_t vrf_id;
    int8_t mac[VR_ETHER_ALEN];
    uint32_t label;
    // Note: this nexthop has only the nh_id field set, but that should be fine
    // for now, as no other fields are read.
    struct vr_nexthop nh;
};

static struct bridge bridges[MAX_BRIDGES];
static size_t n_bridges = 0;

void
add_nh_to_bridge_table(
    uint32_t vrf_id,
    uint8_t *mac,
    uint32_t nh_id,
    uint32_t label
)
{
    assert(n_bridges < MAX_BRIDGES);
    bridges[n_bridges] = (struct bridge) {
        .vrf_id = vrf_id,
        .label = label,
        .nh = {
            .nh_id = nh_id,
        },
    };
    memcpy(&bridges[n_bridges].mac, mac, VR_ETHER_ALEN);
    ++n_bridges;
}

struct vr_nexthop *
vr_bridge_lookup(unsigned int vrf_id, struct vr_route_req *rtr)
{
    if (rtr->rtr_req.rtr_mac_size != VR_ETHER_ALEN) {
        rtr->rtr_nh = NULL;
        return NULL;
    }

    // Note: Iterating in reverse order to support cases in which
    // add_nh_to_route_table overwrites previous entries
    ssize_t i;
    for (i = n_bridges - 1; i >= 0; --i) {
        if (vrf_id == bridges[i].vrf_id
                && memcmp(&bridges[i].mac, rtr->rtr_req.rtr_mac, VR_ETHER_ALEN) == 0) {
            // We should set some other fields to fully mock this funcion, but
            // current our current impl cares only about these:
            rtr->rtr_req.rtr_label = bridges[i].label;
            rtr->rtr_nh = &bridges[i].nh;
            return &bridges[i].nh;
        }
    }

    rtr->rtr_nh = NULL;
    return NULL;
}

#define MAX_ROUTES 16

struct route {
    uint32_t vrf_id;
    enum vr_n3k_ip_type type;
    union vr_n3k_ip ip;
    uint32_t label;
    // Note: this nexthop has only the nh_id field set, but that should be fine
    // for now, as no other fields are read.
    struct vr_nexthop nh;
};

static struct route routes[MAX_ROUTES];
static size_t n_routes = 0;

void
reset_route_table(void) {
    n_routes = 0;
    n_bridges = 0;
}

void
add_nh_to_route_table(
    uint32_t vrf_id,
    enum vr_n3k_ip_type type,
    union vr_n3k_ip ip,
    uint32_t nh_id,
    uint32_t label
)
{
    assert(n_routes < MAX_ROUTES);
    routes[n_routes++] = (struct route) {
        .vrf_id = vrf_id,
        .type = type,
        .ip = ip,
        .label = label,
        .nh = {
            .nh_id = nh_id,
        }
    };
}

struct vr_nexthop *
vr_inet_route_lookup(unsigned int vrf_id, struct vr_route_req * rtr) {
    if (rtr->rtr_req.rtr_family != AF_INET &&
        rtr->rtr_req.rtr_family != AF_INET6) {
        rtr->rtr_nh = NULL;
        return NULL;
    }

    // Note: Iterating in reverse order to support cases in which
    // add_nh_to_route_table overwrites previous entries
    ssize_t i;
    for (i = n_routes - 1; i >= 0; --i) {
        if (vrf_id == routes[i].vrf_id &&
            memcmp(&routes[i].ip, rtr->rtr_req.rtr_prefix,
                rtr->rtr_req.rtr_prefix_size) == 0) {
            // We should set some other fields to fully mock this funcion, but
            // current our current impl cares only about these:
            rtr->rtr_req.rtr_label = routes[i].label;
            rtr->rtr_nh = &routes[i].nh;
            return &routes[i].nh;
        }
    }

    rtr->rtr_nh = NULL;
    return NULL;
}

struct vr_interface*
create_vif(uint16_t interface_id, uint8_t mirror_id)
{
    static struct vr_dpdk_ethdev ethdev;
    struct vr_interface *vif =
        rte_zmalloc("vr_interface", sizeof(struct vr_interface), 0);
    assert_non_null(vif);
    vif->vif_idx = interface_id;
    vif->vif_mirror_id = mirror_id;
    vif->vif_type = VIF_TYPE_VIRTUAL;
    vif->vif_os = &ethdev;
    mock_vr_dpdk_n3k_offload_interface_insert(vif);
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

struct vr_mirror_entry*
create_offload_mirror(uint32_t id, struct vr_nexthop *nh)
{
    struct vr_mirror_entry *offload_mirror
        = vrouter_get_mirror(0, id);
    assert_non_null(offload_mirror);
    offload_mirror->mir_nh = nh;
    return offload_mirror;
}
