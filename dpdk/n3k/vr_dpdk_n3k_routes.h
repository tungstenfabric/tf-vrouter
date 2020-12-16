/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_ROUTE_H__
#define __VR_DPDK_N3K_ROUTE_H__

#include "vr_defs.h"

typedef struct _vr_route_req vr_route_req;

struct vr_n3k_offload_route_key {
    uint32_t ip;
    uint32_t vrf_id;
};

struct vr_n3k_offload_bridge_key {
    uint8_t mac[VR_ETHER_ALEN];
    uint32_t vrf_id;
};

struct vr_n3k_offload_bridge_value {
    uint32_t label;
    uint32_t nh_id;
};

struct vr_n3k_offload_route_value {
    uint32_t label;
    uint32_t nh_id;
};

int vr_dpdk_n3k_offload_routing_init(
    int bridge_entries, unsigned int max_vrf_count);
int vr_dpdk_n3k_offload_routing_exit(void);
int vr_dpdk_n3k_offload_routing_reset(void);
int vr_dpdk_n3k_offload_routing_add(vr_route_req *req);
int vr_dpdk_n3k_offload_routing_del(vr_route_req *req);

int vr_dpdk_n3k_offload_bridge_add_internal(
    struct vr_n3k_offload_bridge_key *key,
    struct vr_n3k_offload_bridge_value *value);

int vr_dpdk_n3k_offload_route_add_internal(
    uint32_t vrf, uint32_t ip, uint8_t prefix_len,
    struct vr_n3k_offload_route_value *value);

int
vr_dpdk_n3k_offload_route_find(struct vr_n3k_offload_route_key *key,
    struct vr_n3k_offload_route_value *out_value);

int
vr_dpdk_n3k_offload_bridge_find(struct vr_n3k_offload_bridge_key *key,
    struct vr_n3k_offload_bridge_value *out_value);

#endif  // __VR_DPDK_N3K_ROUTE_H__
