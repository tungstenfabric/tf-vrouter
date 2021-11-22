/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_nexthop.h"
#include "offload_entry/vr_dpdk_n3k_offload_entry.h"
#include "vr_dpdk_n3k_flow.h"

#include <rte_log.h>
#include <rte_malloc.h>

#include "vr_dpdk.h"
#include "vr_nexthop.h"
#include "vr_packet.h"

int
vr_dpdk_n3k_offload_nexthop_validate(const struct vr_nexthop* nh)
{
    if (!nh) {
        return -ENOENT;
    }

    /* TODO(n3k): Handle multiple routers */
    if (nh->nh_rid != 0)
        return -ENOTSUP;

    if (vr_nexthop_is_being_edited(nh)) {
        return -EAGAIN;
    }

    if (nh->nh_type == NH_COMPOSITE && nh->nh_component_cnt == 0) {
        RTE_LOG(WARNING, VROUTER, "%s(): Composite nh with 0 components, id = %d\n",
                __func__, nh->nh_id);
        /* This shouldn't usually happen, but check it anyway, so that rest of
         * the code can assume non-zero nh_component_count for all composite
         * nexthops. It should simplify some logic. */
        return -ENOTSUP;
    }

    return 0;
}

const struct vr_nexthop *
vr_dpdk_n3k_offload_nexthop_get(uint32_t id)
{
    /* Note: Using `__vrouter_get_nexthop` instead of `vrouter_get_nexthop`, as
     * the returned pointer will be short-lived (we never persist it). The RCU
     * mechanism guarantees that the pointer will be valid until the next
     * synchronization point. Thus, there's no need to bump the nh refcount via
     * the usage of `vrouter_get_nexthop`. */
    const struct vr_nexthop *nh = __vrouter_get_nexthop(vrouter_get(0), id);

    if (vr_dpdk_n3k_offload_nexthop_validate(nh) != 0) {
        return NULL;
    }

    return nh;
}

/* This needs to be aligned because it could be cast to struct rte_ether_addr */
const uint8_t vr_n3k_offload_zero_mac[VR_ETHER_ALEN] __attribute__((aligned(2))) = {0,};

int vr_dpdk_n3k_offload_nexthop_get_cnh_idx(
    const struct vr_nexthop *nh, uint16_t idx, uint32_t *nh_idx)
{
    if (!nh || nh->nh_type != NH_COMPOSITE)
        return -EINVAL;

    if (idx >= nh->nh_component_cnt) {
        return -EINVAL;
    }

    struct vr_nexthop *cnh = nh->nh_component_nh[idx].cnh;
    if (!cnh) {
        return -ENOENT;
    }

    *nh_idx = cnh->nh_id;
    return 0;
}

int vr_dpdk_n3k_offload_nexthop_get_cnh_label(
    const struct vr_nexthop *nh, uint16_t idx, uint32_t *label)
{
    if (!nh || nh->nh_type != NH_COMPOSITE)
        return -EINVAL;

    if (idx >= nh->nh_component_cnt) {
        return -EINVAL;
    }

    *label = nh->nh_component_nh[idx].cnh_label;
    return 0;
}
