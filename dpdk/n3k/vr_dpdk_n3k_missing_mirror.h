/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_MISSING_MIRROR_H__
#define __VR_DPDK_N3K_MISSING_MIRROR_H__

#include "offload_entry/vr_dpdk_n3k_offload_entry.h"

#include <rte_hash.h>
#include <rte_log.h>
#include <rte_malloc.h>

#include "vr_dpdk.h"

void vr_dpdk_n3k_offload_missing_mirrors_exit();
void vr_dpdk_n3k_offload_missing_mirror_vifs_exit();
void vr_dpdk_n3k_offload_missing_mirror_nexthops_exit();

int vr_dpdk_n3k_offload_missing_mirrors_init(size_t table_size);
int vr_dpdk_n3k_offload_missing_mirror_vifs_init(size_t table_size);
int vr_dpdk_n3k_offload_missing_mirror_nexthops_init(size_t table_size);

int vr_dpdk_n3k_offload_missing_mirrors_add(uint32_t id,
                                            uint32_t flow_id);
int vr_dpdk_n3k_offload_missing_mirror_vifs_add(uint32_t id,
                                                uint32_t flow_id);
int vr_dpdk_n3k_offload_missing_mirror_nexthops_add(uint32_t id,
                                                    uint32_t flow_id);

void vr_dpdk_n3k_offload_missing_mirror_flows(uint32_t id);
void vr_dpdk_n3k_offload_missing_vif_flows(uint32_t id);
void vr_dpdk_n3k_offload_missing_nexthop_flows(uint32_t id);

#endif // __VR_DPDK_N3K_MISSING_MIRROR_H__