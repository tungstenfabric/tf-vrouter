/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_INT_TEST_UTILS_H__
#define __VR_DPDK_N3K_INT_TEST_UTILS_H__

#include "vr_dpdk_n3k_flow.h"
#include "vr_dpdk_n3k_interface.h"
#include "vr_dpdk_n3k_mirror.h"
#include "vr_dpdk_n3k_nexthop.h"
#include "vr_dpdk_n3k_flow.h"
#include "vr_dpdk_n3k_packet_metadata.h"

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
);

struct vr_dpdk_n3k_packet_key
create_packet_key(
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t nh_id
);

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
);

struct vr_n3k_offload_nexthop *
create_offload_nexthop(
    uint32_t nh_id,
    uint8_t type,
    uint32_t flags,
    uint16_t interface_id,
    uint8_t family
);

struct vr_n3k_offload_nexthop *
create_offload_nexthop_composite(
    uint32_t nh_id,
    uint8_t type,
    uint32_t flags,
    uint16_t interface_id,
    uint8_t family,
    uint16_t component_cnt,
    struct vr_n3k_offload_nh_label * component_nhs
);

void
add_nh_to_bridge_table(
    uint32_t vrf_id,
    uint8_t *mac,
    uint32_t nh_id,
    uint32_t vni
);

void
add_nh_to_route_table(
    uint32_t vrf_id,
    uint32_t ip,
    uint32_t nh_id,
    uint32_t label
);

struct vr_n3k_offload_interface *
create_vif(uint16_t interface_id, uint8_t mirror_id);

void
check_packet_metadata(
    struct vr_dpdk_n3k_packet_metadata *test_metadata,
    struct vr_dpdk_n3k_packet_metadata *good_metadata
);

struct vr_n3k_offload_mirror *
create_offload_mirror(uint32_t id, uint32_t nexthop_id);

void
check_offload_entry(
    struct vr_n3k_offload_entry *test_entry,
    struct vr_n3k_offload_entry *good_entry
);

#endif /* __VR_DPDK_N3K_INT_TEST_UTILS_H__ */
