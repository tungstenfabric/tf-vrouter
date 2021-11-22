/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_mpls.h"

#include <assert.h>
#include <string.h>
#include <sys/queue.h>

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include "vr_dpdk.h"

enum { N3K_OFFLOAD_MPLS_LABEL_COUNT = 1 << 20 };

#define EMPTY_LABEL UINT32_MAX

struct vr_n3k_offload_mpls_entry {
    struct vr_n3k_offload_mpls value;
    STAILQ_ENTRY(vr_n3k_offload_mpls_entry) entries;
};

static bool entry_is_empty(const struct vr_n3k_offload_mpls_entry *entry) {
    return entry->value.label == EMPTY_LABEL;
}

STAILQ_HEAD(vr_n3k_nh_to_labels_list, vr_n3k_offload_mpls_entry);

struct vr_n3k_nh_to_labels {
    struct vr_n3k_nh_to_labels_list list;
    size_t count;
};

static uint32_t nexthops_count;

/* Invariant: !entry_is_empty(&label_to_nh[label]) iff.
 *     nh_to_labels[label_to_nh[label].value.nexthop_id].list contains &label_to_nh[label] */
static struct vr_n3k_offload_mpls_entry *label_to_nh;
static struct vr_n3k_nh_to_labels *nh_to_labels;

static rte_rwlock_t mpls_lock __rte_cache_aligned;

int
vr_dpdk_n3k_offload_mpls_init(uint32_t nh_count)
{
    int idx;

    rte_rwlock_init(&mpls_lock);

    label_to_nh = rte_malloc("n3k_offload_mpls",
            N3K_OFFLOAD_MPLS_LABEL_COUNT * sizeof(*label_to_nh), 0);
    if (label_to_nh == NULL)
        return -ENOMEM;

    /* set label_to_nh[*].value.label = EMPTY_LABEL */
    memset(label_to_nh, 0xff, N3K_OFFLOAD_MPLS_LABEL_COUNT * sizeof(*label_to_nh));

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

static void
vr_dpdk_n3k_offload_mpls_insert(struct vr_n3k_offload_mpls mpls)
{
    struct vr_n3k_offload_mpls_entry *entry = &label_to_nh[mpls.label];
    assert(entry_is_empty(entry));

    entry->value = mpls;

    struct vr_n3k_nh_to_labels *labels = &nh_to_labels[mpls.nexthop_id];
    STAILQ_INSERT_HEAD(&labels->list, entry, entries);
    labels->count++;
}

int
vr_dpdk_n3k_offload_mpls_insert_copy_for_test(struct vr_n3k_offload_mpls mpls)
{
    if (!entry_is_empty(&label_to_nh[mpls.label]))
        return -EEXIST;

    rte_rwlock_write_lock(&mpls_lock);
    vr_dpdk_n3k_offload_mpls_insert(mpls);
    rte_rwlock_write_unlock(&mpls_lock);

    return 0;
}

/* Removes mapping, if exists.
 * @returns
 *     true if mapping existed and had been removed,
 *     false is mapping did not exist */
static bool
vr_dpdk_n3k_offload_mpls_remove_mapping(int label)
{
    struct vr_n3k_offload_mpls_entry *entry = &label_to_nh[label];
    if (entry_is_empty(entry)) {
        return false;
    }

    struct vr_n3k_nh_to_labels *labels = &nh_to_labels[entry->value.nexthop_id];
    STAILQ_REMOVE(&labels->list, entry, vr_n3k_offload_mpls_entry, entries);
    labels->count--;

    label_to_nh[label].value.label = EMPTY_LABEL;

    return true;
}

void
vr_dpdk_n3k_offload_mpls_exit(void)
{
    rte_free(nh_to_labels);
    nh_to_labels = NULL;

    rte_free(label_to_nh);
    label_to_nh = NULL;
}

extern int __attribute__((weak))
   vr_dpdk_n3k_offload_mpls_get_by_label(uint32_t label, struct vr_n3k_offload_mpls *);

int
vr_dpdk_n3k_offload_mpls_get_by_label(uint32_t label, struct vr_n3k_offload_mpls * out)
{
    if (label >= N3K_OFFLOAD_MPLS_LABEL_COUNT)
        return -EINVAL;

    rte_rwlock_read_lock(&mpls_lock);

    if (label_to_nh[label].value.label == EMPTY_LABEL) {
        rte_rwlock_read_unlock(&mpls_lock);
        return -ENOENT;
    }
    *out = label_to_nh[label].value;

    rte_rwlock_read_unlock(&mpls_lock);

    return 0;
}

int
vr_dpdk_n3k_offload_mpls_get_by_nh(uint32_t nh_id, struct vr_n3k_offload_mpls * out)
{
    if (nh_id >= nexthops_count)
        return -EINVAL;

    rte_rwlock_read_lock(&mpls_lock);
    struct vr_n3k_nh_to_labels *labels = &nh_to_labels[nh_id];
    if (labels->count == 0) {
        rte_rwlock_read_unlock(&mpls_lock);
        return -ENOENT;
    }

    if (labels->count != 1) {
        rte_rwlock_read_unlock(&mpls_lock);
        RTE_LOG(WARNING, VROUTER,
            "%s(): Multiple MPLS labels found for nh=%d\n", __func__, nh_id);
        return -ENOTSUP;
    }

    *out = STAILQ_FIRST(&labels->list)->value;
    rte_rwlock_read_unlock(&mpls_lock);

    return 0;
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

    rte_rwlock_write_lock(&mpls_lock);

    uint32_t old_nh_id = label_to_nh[label].value.nexthop_id;
    bool mapping_removed = vr_dpdk_n3k_offload_mpls_remove_mapping(label);

    vr_dpdk_n3k_offload_mpls_insert((struct vr_n3k_offload_mpls) {
            .label = label,
            .nexthop_id = nh->nh_id,
    });

    rte_rwlock_write_unlock(&mpls_lock);

    if (mapping_removed) {
        RTE_LOG(
            WARNING, VROUTER,
            "%s(): nh=%p; nh_id=%u; label=%d; "
            "WARNING, label already offloaded; previous entry: nh_id=%u;\n",
            __func__, nh, nh->nh_id, label, old_nh_id
        );
    }

    return 0;
}

int
vr_dpdk_n3k_offload_mpls_del(int label)
{
    RTE_LOG(DEBUG, VROUTER, "%s() called; label=%d\n", __func__, label);

    if (label < 0 || label >= N3K_OFFLOAD_MPLS_LABEL_COUNT)
        return -EINVAL;

    rte_rwlock_write_lock(&mpls_lock);
    vr_dpdk_n3k_offload_mpls_remove_mapping(label);
    rte_rwlock_write_unlock(&mpls_lock);

    return 0;
}
