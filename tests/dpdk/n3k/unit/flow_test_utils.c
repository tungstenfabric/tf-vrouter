/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "flow_test_utils.h"

bool
cmp_patterns(struct rte_flow_item *items,
             enum rte_flow_item_type *expected_types)
{
    int l = 0, r = 0;
    while (expected_types[r] != RTE_FLOW_ITEM_TYPE_END) {
        if (items[l].type == RTE_FLOW_ITEM_TYPE_VOID) {
            ++l;
            continue;
        }
        if (items[l].type == expected_types[r]) {
            ++r;
            ++l;
        } else {
            return false;
        }
    }

    while (items[l].type == RTE_FLOW_ITEM_TYPE_VOID) ++l;

    return items[l].type == RTE_FLOW_ITEM_TYPE_END;
}

bool
cmp_actions(struct rte_flow_action *items,
            enum rte_flow_action_type *expected_types)
{
    int l = 0, r = 0;
    while (expected_types[r] != RTE_FLOW_ACTION_TYPE_END) {
        if (items[l].type == RTE_FLOW_ACTION_TYPE_VOID) {
            ++l;
            continue;
        }
        if (items[l].type == expected_types[r]) {
            ++r;
            ++l;
        } else {
            return false;
        }
    }

    while (items[l].type == RTE_FLOW_ACTION_TYPE_VOID) ++l;

    return items[l].type == RTE_FLOW_ACTION_TYPE_END;
}
