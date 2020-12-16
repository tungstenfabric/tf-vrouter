/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "offload_entry/vr_dpdk_n3k_offload_entry.h"
#include "vr_dpdk_n3k_mirror.h"
#include "vr_dpdk_n3k_missing_mirror.h"

#include <rte_log.h>
#include <rte_malloc.h>

#include "vr_dpdk.h"
#include "vr_mirror.h"

static uint32_t mirrors_count;
static struct vr_n3k_offload_mirror **mirrors;

int
vr_dpdk_n3k_offload_mirror_init(uint32_t count)
{
    mirrors = rte_zmalloc("n3k_offload_mirror", count * sizeof(*mirrors), 0);
    if (mirrors == NULL)
        return -ENOMEM;

    mirrors_count = count;

    if (vr_dpdk_n3k_offload_missing_mirrors_init(128) != 0)
        return -1;

    return 0;
}

void
vr_dpdk_n3k_offload_mirror_exit(void)
{
    int idx;

    for (idx = 0; idx < mirrors_count; ++idx) {
        rte_free(mirrors[idx]);
        mirrors[idx] = NULL;
    }

    rte_free(mirrors);
    mirrors = NULL;

    vr_dpdk_n3k_offload_missing_mirrors_exit();
}

struct vr_n3k_offload_mirror *
vr_dpdk_n3k_offload_mirror_get(uint32_t id)
{
    if (id >= mirrors_count)
        return NULL;

    return mirrors[id];
}

void
vr_dpdk_n3k_offload_mirror_insert(struct vr_n3k_offload_mirror *mirror)
{
    mirrors[mirror->id] = mirror;
}

int
vr_dpdk_n3k_offload_mirror_add(
    struct vr_mirror_entry *mirror, unsigned int index)
{
    RTE_LOG(DEBUG, VROUTER, "%s() called; mirror=%p; index=%u\n",
        __func__, mirror, index);

    /* TODO(n3k): Handle multiple routers */
    if (mirror->mir_rid != 0)
        return 0;

    if (mirror->mir_nh == NULL) {
        RTE_LOG(ERR, VROUTER, "%s(): Nexthop is NULL\n", __func__);
        return -EINVAL;
    }

    struct vr_n3k_offload_mirror *omirror = mirrors[index];

    /* TODO(n3k): What to do when existing mirror has been changed? */

    if (omirror == NULL) {
        omirror = rte_zmalloc("n3k_offload_mirror", sizeof(*omirror), 0);
        if (omirror == NULL)
            return -ENOMEM;
    }

    omirror->id = index;
    omirror->nexthop_id = mirror->mir_nh->nh_id;

    vr_dpdk_n3k_offload_mirror_insert(omirror);

    vr_dpdk_n3k_offload_missing_mirror_flows(index);

    return 0;
}

int
vr_dpdk_n3k_offload_mirror_del(uint32_t index)
{
    RTE_LOG(DEBUG, VROUTER, "%s() called; index=%u\n", __func__, index);

    rte_free(mirrors[index]);
    mirrors[index] = NULL;

    return 0;
}
