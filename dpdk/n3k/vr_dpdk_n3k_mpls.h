/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_MPLS_H__
#define __VR_DPDK_N3K_MPLS_H__

#include <rte_byteorder.h>
#include "vr_defs.h"

struct vr_nexthop;

struct vr_n3k_offload_mpls {
    rte_le32_t label;
    uint32_t nexthop_id;
};

int vr_dpdk_n3k_offload_mpls_init(uint32_t nh_count);
void vr_dpdk_n3k_offload_mpls_exit(void);

/* All the structures in this module are protected by internal lock, so all the
 * getters are threadsafe. */
int vr_dpdk_n3k_offload_mpls_get_by_label(uint32_t label, struct vr_n3k_offload_mpls *out);
int vr_dpdk_n3k_offload_mpls_get_by_nh(uint32_t nh_id, struct vr_n3k_offload_mpls *out);

/* Inserts mpls-nexthop mapping.
 * This function is exposed only for integration tests.
 * @returns 0 or -EEXIST */
int vr_dpdk_n3k_offload_mpls_insert_copy_for_test(struct vr_n3k_offload_mpls mpls);

/* These functions are threadsafe */
int vr_dpdk_n3k_offload_mpls_add(struct vr_nexthop *nh, int label);
int vr_dpdk_n3k_offload_mpls_del(int label);

#endif // __VR_DPDK_N3K_MPLS_H__
