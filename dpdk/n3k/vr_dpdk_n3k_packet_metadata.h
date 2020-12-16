/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_PACKET_METADATA_H__
#define __VR_DPDK_N3K_PACKET_METADATA_H__

#include <stdint.h>
#include <stdbool.h>

#include <rte_byteorder.h>

#include <vr_defs.h>


struct vr_n3k_offload_flow;

struct vr_dpdk_n3k_packet_key {
    rte_le32_t nh_id;
    rte_be32_t src_ip;
    rte_be32_t dst_ip;
    uint8_t  proto;
    rte_be16_t src_port;
    rte_be16_t dst_port;
};

struct vr_dpdk_n3k_packet_metadata {
    bool eth_hdr_present;
    uint8_t inner_src_mac[VR_ETHER_ALEN];
    uint8_t inner_dst_mac[VR_ETHER_ALEN];
};

int vr_dpdk_n3k_packet_metadata_init(size_t);
int vr_dpdk_n3k_packet_metadata_exit(void);
void vr_dpdk_n3k_packet_metadata_reset(void);

int vr_dpdk_n3k_packet_metadata_insert_copy(struct vr_dpdk_n3k_packet_key *key,
    struct vr_dpdk_n3k_packet_metadata *value);

int vr_dpdk_n3k_packet_metadata_delete(struct vr_dpdk_n3k_packet_key *key);

int vr_dpdk_n3k_packet_metadata_find_by_flow(
    const struct vr_n3k_offload_flow *flow,
    struct vr_dpdk_n3k_packet_metadata *out_value);

void vr_dpdk_n3k_packet_metadata_fill_key_from_flow(
    const struct vr_n3k_offload_flow *flow,
    struct vr_dpdk_n3k_packet_key *key);

int vr_dpdk_n3k_packet_metadata_ensure_entry_for_flow_exists(
    struct vr_n3k_offload_flow *flow,
    struct vr_n3k_offload_flow *reverse_flow);

#endif  // __VR_DPDK_N3K_PACKET_METADATA_H__
