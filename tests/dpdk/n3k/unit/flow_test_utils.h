/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __FLOW_TEST_UTILS_H__
#define __FLOW_TEST_UTILS_H__

#include <rte_flow.h>
#include <stdbool.h>

#define VXLAN_MASK 0x00FFFFFF

typedef union ipv4_t {
    uint8_t addr[4];
    uint32_t value;
} ipv4_t;

bool
cmp_patterns(struct rte_flow_item *items,
             enum rte_flow_item_type *expected_types);

bool
cmp_actions(struct rte_flow_action *items,
            enum rte_flow_action_type *expected_types);

#endif /* __FLOW_TEST_UTILS_H__ */
