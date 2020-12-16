/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_INT_TEST_UTILS_MPLSOUDP_H__
#define __VR_DPDK_N3K_INT_TEST_UTILS_MPLSOUDP_H__

#include "vr_dpdk_n3k_mpls.h"
#include "vr_dpdk_n3k_packet_metadata.h"

struct vr_dpdk_n3k_packet_metadata
create_packet_metadata_for_mplsoudp(
    uint8_t* overlay_src_mac,
    uint8_t* overlay_dst_mac,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t nh_id,
    bool eth_hdr
);

struct vr_n3k_offload_mpls *
create_offload_mpls(uint32_t label, uint32_t nexthop_id);

void
check_offload_entry_mplsoudp(
    struct vr_n3k_offload_entry *test_entry,
    struct vr_n3k_offload_entry *good_entry
);

#endif /* __VR_DPDK_N3K_INT_TEST_UTILS_MPLSOUDP_H__ */
