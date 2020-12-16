/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_MIRROR_H__
#define __VR_DPDK_N3K_MIRROR_H__

#include "vr_defs.h"

struct vr_mirror_entry;

struct vr_n3k_offload_mirror {
    uint32_t id;
    uint32_t nexthop_id;
};

int vr_dpdk_n3k_offload_mirror_init(uint32_t count);
void vr_dpdk_n3k_offload_mirror_exit(void);
struct vr_n3k_offload_mirror *vr_dpdk_n3k_offload_mirror_get(uint32_t id);

void vr_dpdk_n3k_offload_mirror_insert(struct vr_n3k_offload_mirror *mirror);
int vr_dpdk_n3k_offload_mirror_add(struct vr_mirror_entry *mirror, uint32_t index);
int vr_dpdk_n3k_offload_mirror_del(uint32_t index);

#endif // __VR_DPDK_N3K_MIRROR_H__
