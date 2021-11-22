/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "flow_test_utils.h"

#include <assert.h>

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

/* Stubbed vrouter functions */

struct vr_route_req;
struct vr_nexthop;
struct vr_nexthop *
vr_inet_route_lookup(unsigned int vrf_id, struct vr_route_req * rtr) {
    return NULL;
}

/* This functions definition is only to satisfy linker */
struct vr_nexthop *
vr_bridge_lookup(unsigned int vrf_id, struct vr_route_req * rtr) {
    assert(false && "vr_bridge_lookup should not be called from tests");
}
