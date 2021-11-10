/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_INT_TEST_UTILS_VXLAN_H__
#define __VR_DPDK_N3K_INT_TEST_UTILS_VXLAN_H__

#include "vr_dpdk_n3k_vxlan.h"
#include "vr_dpdk_n3k_packet_metadata.h"

struct vr_dpdk_n3k_packet_metadata
create_packet_metadata_for_vxlan(
    uint8_t* overlay_src_mac,
    uint8_t* overlay_dst_mac,
    struct vr_n3k_ips *ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t nh_id
);

void create_offload_vxlan(uint32_t vnid, uint32_t nexthop_id);

void
check_offload_entry_vxlan(
    struct vr_n3k_offload_entry *test_entry,
    struct vr_n3k_offload_entry *good_entry
);

#endif /* __VR_DPDK_N3K_INT_TEST_UTILS_VXLAN_H__ */
