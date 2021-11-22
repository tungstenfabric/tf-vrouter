/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_OFFLOAD_HOLD_H__
#define __VR_DPDK_N3K_OFFLOAD_HOLD_H__

#include <stdbool.h>
#include <vr_flow.h>
#include <vr_offloads.h>
#include "vr_dpdk_n3k_flow.h"

int
vr_dpdk_n3k_offload_hold_init(size_t table_size);

void
vr_dpdk_n3k_offload_hold_exit();

bool
vr_dpdk_n3k_offload_hold_entry_exist(struct vr_n3k_offload_flow *flow);

bool
vr_dpdk_n3k_offload_hold_should_wait(struct vr_n3k_offload_flow *fe,
    struct vr_n3k_offload_flow *rfe);

int
vr_dpdk_n3k_offload_hold_save_flow(const struct vr_n3k_offload_flow *flow);

bool
vr_dpdk_n3k_offload_hold_get_held(struct vr_n3k_offload_flow *flow,
    struct vr_n3k_offload_flow **reverse_flow);

void
vr_dpdk_n3k_offload_hold_del_flow(const struct vr_n3k_offload_flow* flow);

#endif // __VR_DPDK_N3K_OFFLOAD_HOLD_H__
