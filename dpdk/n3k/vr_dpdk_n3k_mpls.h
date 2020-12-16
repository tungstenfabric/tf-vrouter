/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_MPLS_H__
#define __VR_DPDK_N3K_MPLS_H__

#include <sys/queue.h>
#include <rte_byteorder.h>
#include "vr_defs.h"

struct vr_nexthop;

struct vr_n3k_offload_mpls {
    rte_le32_t label;
    uint32_t nexthop_id;
    STAILQ_ENTRY(vr_n3k_offload_mpls) entries;
};

int vr_dpdk_n3k_offload_mpls_init(uint32_t nh_count);
void vr_dpdk_n3k_offload_mpls_exit(void);
struct vr_n3k_offload_mpls *vr_dpdk_n3k_offload_mpls_get_by_label(uint32_t label);
struct vr_n3k_offload_mpls *vr_dpdk_n3k_offload_mpls_get_by_nh(uint32_t nh_id);

void vr_dpdk_n3k_offload_mpls_insert(struct vr_n3k_offload_mpls *mpls);
int vr_dpdk_n3k_offload_mpls_add(struct vr_nexthop *nh, int label);
int vr_dpdk_n3k_offload_mpls_del(int label);

#endif // __VR_DPDK_N3K_MPLS_H__
