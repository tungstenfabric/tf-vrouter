/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_OFFLOAD_CONVERTER_H__
#define __VR_DPDK_N3K_OFFLOAD_CONVERTER_H__

#include "vr_dpdk_n3k_rte_flow_package.h"

struct vr_n3k_offload_entry;

struct vr_n3k_rte_flow_package
vr_dpdk_n3k_offload_entry_to_rte_flow(struct vr_n3k_offload_entry *entry);

#endif // __VR_DPDK_N3K_OFFLOAD_CONVERTER_H__
