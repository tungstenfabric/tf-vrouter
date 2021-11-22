/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_OFFLOADS_H__
#define __VR_DPDK_N3K_OFFLOADS_H__

#include <rte_spinlock.h>

int vr_dpdk_n3k_offload_init(void);
void vr_dpdk_n3k_offload_exit(void);

extern rte_spinlock_t vr_dpdk_n3k_offload_spinlock;

static inline void
vr_dpdk_n3k_offload_lock(void)
{
    rte_spinlock_lock(&vr_dpdk_n3k_offload_spinlock);
}

static inline void
vr_dpdk_n3k_offload_unlock(void)
{
    rte_spinlock_unlock(&vr_dpdk_n3k_offload_spinlock);
}

#endif // __VR_DPDK_N3K_OFFLOADS_H__
