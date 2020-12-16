/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_FLOW_H__
#define __VR_DPDK_N3K_FLOW_H__

#include <rte_byteorder.h>
#include "offload_entry/vr_dpdk_n3k_offload_entry.h"
#include "vr_defs.h"

struct vr_flow_entry;
struct rte_flow;

struct vr_n3k_offload_stats {
    uint64_t packets;
    uint64_t bytes;
};

struct vr_n3k_offload_flow {
    uint32_t id;
    uint32_t reverse_id;
    uint16_t action;
    uint16_t flags;
    uint16_t tcp_flags;
    rte_be32_t src_ip;
    rte_be32_t dst_ip;
    uint8_t proto;
    rte_be16_t src_port;
    rte_be16_t dst_port;
    rte_be16_t tunnel_udp_src_port;
    uint32_t nh_id;
    uint16_t src_vrf_id;
    uint8_t mirror_id;
    int8_t ecmp_nh_idx;

    struct vr_n3k_offload_stats stats;
    struct rte_flow *handle;
    uint16_t hw_port_id;
};

struct vr_n3k_offload_flowtable_key {
    uint32_t fe_index;
};

struct vr_n3k_offload_flow *
vr_dpdk_n3k_offload_flow_get(struct vr_n3k_offload_flowtable_key *key);

int vr_dpdk_n3k_offload_flow_init(size_t);
void vr_dpdk_n3k_offload_flow_exit(void);

int vr_dpdk_n3k_offload_flow_table_add(
    struct vr_n3k_offload_flowtable_key *key,
    struct vr_n3k_offload_flow *flow);

int vr_dpdk_n3k_offload_flow_set(
    struct vr_flow_entry *fe, uint32_t fe_index, struct vr_flow_entry *rfe);
int vr_dpdk_n3k_offload_flow_del(struct vr_flow_entry *fe);
int vr_dpdk_n3k_offload_flow_stats_update(struct vr_flow_entry *fe);
void vr_dpdk_n3k_offload_flow_vif_update(struct vr_n3k_offload_interface *vif);
int vr_dpdk_n3k_offload_flow_update_with_offload_entry(
    struct vr_n3k_offload_flow *flow,
    struct vr_n3k_offload_entry *offload_entry);
int vr_dpdk_n3k_offload_flow_update(
    struct vr_n3k_offload_flow *flow);
#endif // __VR_DPDK_N3K_FLOW_H__
