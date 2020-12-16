/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_RTE_FLOW_PACKAGE_H__
#define __VR_DPDK_N3K_RTE_FLOW_PACKAGE_H__

#include <rte_flow.h>

struct vr_n3k_rte_flow_package {
    int error;
    struct rte_flow_item *pattern;
    struct rte_flow_action *actions;
};

#endif // __VR_DPDK_N3K_RTE_FLOW_PACKAGE_H__
