/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_mpls.h"

#include <assert.h>

#include <rte_log.h>
#include <rte_malloc.h>

#include "vr_dpdk.h"

enum { N3K_OFFLOAD_MPLS_LABEL_COUNT = 1 << 20 };

STAILQ_HEAD(vr_n3k_nh_to_labels_list, vr_n3k_offload_mpls);

struct vr_n3k_nh_to_labels {
    struct vr_n3k_nh_to_labels_list list;
    size_t count;
};

static uint32_t nexthops_count;
static struct vr_n3k_offload_mpls **label_to_nh;
static struct vr_n3k_nh_to_labels *nh_to_labels;

int
vr_dpdk_n3k_offload_mpls_init(uint32_t nh_count)
{
    int idx;

    label_to_nh = rte_zmalloc("n3k_offload_mpls",
            N3K_OFFLOAD_MPLS_LABEL_COUNT * sizeof(*label_to_nh), 0);
    if (label_to_nh == NULL)
        return -ENOMEM;

    nh_to_labels = rte_zmalloc(
        "n3k_offload_mpls", nh_count * sizeof(*nh_to_labels), 0);
    if (nh_to_labels == NULL) {
        rte_free(label_to_nh);
        return -ENOMEM;
    }

    for (idx = 0; idx < nh_count; ++idx) {
        STAILQ_INIT(&nh_to_labels[idx].list);
    }

    nexthops_count = nh_count;

    return 0;
}

void
vr_dpdk_n3k_offload_mpls_insert(struct vr_n3k_offload_mpls *mpls)
{
    label_to_nh[mpls->label] = mpls;

    struct vr_n3k_nh_to_labels *labels = &nh_to_labels[mpls->nexthop_id];
    STAILQ_INSERT_HEAD(&labels->list, mpls, entries);
    labels->count++;
}

static void
vr_dpdk_n3k_offload_mpls_remove_nh_to_label_mapping(
    struct vr_n3k_offload_mpls *mpls)
{
    struct vr_n3k_offload_mpls *iter;
    bool found = false;

    struct vr_n3k_nh_to_labels *labels = &nh_to_labels[mpls->nexthop_id];
    STAILQ_FOREACH(iter, &labels->list, entries) {
        if (iter == mpls) {
            found = true;
            break;
        }
    }

    if (found) {
        STAILQ_REMOVE(&labels->list, mpls, vr_n3k_offload_mpls, entries);
        labels->count--;
    }
}

static void
vr_dpdk_n3k_offload_mpls_free(struct vr_n3k_offload_mpls *mpls)
{
    if (mpls == NULL)
        return;

    label_to_nh[mpls->label] = NULL;
    vr_dpdk_n3k_offload_mpls_remove_nh_to_label_mapping(mpls);

    rte_free(mpls);
}

void
vr_dpdk_n3k_offload_mpls_exit(void)
{
    int label;

    for (label = 0; label < N3K_OFFLOAD_MPLS_LABEL_COUNT; ++label)
        vr_dpdk_n3k_offload_mpls_free(label_to_nh[label]);

    rte_free(nh_to_labels);
    nh_to_labels = NULL;

    rte_free(label_to_nh);
    label_to_nh = NULL;
}

extern  struct vr_n3k_offload_mpls * __attribute__((weak))
   vr_dpdk_n3k_offload_mpls_get_by_label(uint32_t label);

struct vr_n3k_offload_mpls *
vr_dpdk_n3k_offload_mpls_get_by_label(uint32_t label)
{
    RTE_LOG(DEBUG, VROUTER, "%s() called; label=%d\n", __func__, label);

    if (label >= N3K_OFFLOAD_MPLS_LABEL_COUNT)
        return NULL;

    return label_to_nh[label];
}

struct vr_n3k_offload_mpls *
vr_dpdk_n3k_offload_mpls_get_by_nh(uint32_t nh_id)
{
    RTE_LOG(DEBUG, VROUTER, "%s() called; nh_id=%u\n", __func__, nh_id);

    if (nh_id >= nexthops_count)
        return NULL;

    struct vr_n3k_nh_to_labels *labels = &nh_to_labels[nh_id];
    if (labels->count == 0)
        return NULL;

    if (labels->count != 1) {
        RTE_LOG(WARNING, VROUTER,
            "%s(): Multiple MPLS labels found for nh=%d\n", __func__, nh_id);
        return NULL;
    }

    return STAILQ_FIRST(&labels->list);
}

int
vr_dpdk_n3k_offload_mpls_add(struct vr_nexthop *nh, int label)
{
    if(nh == NULL) {
        RTE_LOG(DEBUG, VROUTER, "%s() called; nh=NULL\n", __func__);
        return -EINVAL;
    }

    RTE_LOG(
        DEBUG, VROUTER,
        "%s() called; nh=%p; nh_id=%d; nh_type=%d; label=%d;\n",
        __func__, nh, nh->nh_id, nh->nh_type, label
    );

    if (nh->nh_id >= nexthops_count)
        return -EINVAL;

    /* TODO(n3k): Handle multiple routers */
    if (nh->nh_rid != 0)
        return -EINVAL;

    if (label < 0 || label >= N3K_OFFLOAD_MPLS_LABEL_COUNT)
        return -EINVAL;

    struct vr_n3k_offload_mpls *ompls = label_to_nh[label];

    if (ompls == NULL) {
        ompls = rte_zmalloc("n3k_offload_mpls", sizeof(*ompls), 0);
        if (ompls == NULL)
            return -ENOMEM;
    } else {
        RTE_LOG(
            WARNING, VROUTER,
            "%s(): nh=%p; nh_id=%u; label=%d; "
            "WARNING, label already offloaded; previous entry: nh_id=%u;\n",
            __func__, nh, nh->nh_id, label, ompls->nexthop_id
        );

        vr_dpdk_n3k_offload_mpls_remove_nh_to_label_mapping(ompls);
    }

    ompls->label = label;
    ompls->nexthop_id = nh->nh_id;

    vr_dpdk_n3k_offload_mpls_insert(ompls);

    return 0;
}

int
vr_dpdk_n3k_offload_mpls_del(int label)
{
    RTE_LOG(DEBUG, VROUTER, "%s() called; label=%d\n", __func__, label);

    if (label < 0 || label >= N3K_OFFLOAD_MPLS_LABEL_COUNT)
        return -EINVAL;

    vr_dpdk_n3k_offload_mpls_free(label_to_nh[label]);

    return 0;
}
