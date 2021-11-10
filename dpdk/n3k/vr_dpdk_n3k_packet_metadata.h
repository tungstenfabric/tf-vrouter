/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_PACKET_METADATA_H__
#define __VR_DPDK_N3K_PACKET_METADATA_H__

#include <time.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_byteorder.h>

#include <vr_defs.h>

#include "vr_dpdk_n3k_ip.h"

/* Lifetime of packet metadata:
    One packet metadata has direct mapping to the corresponding flow
    (or no at all if the flow hasn't been created), but setting
    the lifetime of packet metadata to the corresponding flow's
    could result in blockage of vRouter's packet processing as the hashtable
    can also hold packet metadatas that won't result in flow creation.
    However if the value would be too small, then in large traffic
    scenarios there could be situation where flow being created has
    no corresponding metadata, which must not happen.

    Value has been selected empirically.
*/
#define VR_DPDK_N3K_PACKET_METADATA_TIMEOUT 8

struct vr_n3k_offload_flow;

struct vr_dpdk_n3k_packet_key {
    rte_le32_t nh_id;
    rte_be16_t src_port;
    rte_be16_t dst_port;
    struct vr_n3k_ips ip;
    uint8_t  proto;
};

struct vr_dpdk_n3k_packet_metadata {
    bool eth_hdr_present;
    uint8_t inner_src_mac[VR_ETHER_ALEN];
    uint8_t inner_dst_mac[VR_ETHER_ALEN];
    time_t creation_timestamp;
};

int vr_dpdk_n3k_packet_metadata_init(size_t);
int vr_dpdk_n3k_packet_metadata_exit(void);
void vr_dpdk_n3k_packet_metadata_reset(void);

void vr_dpdk_n3k_packet_metadata_remove_unused(void);

int vr_dpdk_n3k_packet_metadata_insert_copy(struct vr_dpdk_n3k_packet_key *key,
    struct vr_dpdk_n3k_packet_metadata *value, bool existing_flow_metadata);

int vr_dpdk_n3k_packet_metadata_delete(struct vr_dpdk_n3k_packet_key *key);

void
vr_dpdk_n3k_packet_metadata_mark_used(struct vr_n3k_offload_flow *flow);

void
vr_dpdk_n3k_packet_metadata_schedule_delete(struct vr_n3k_offload_flow *flow);

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
