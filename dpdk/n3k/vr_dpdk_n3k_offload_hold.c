/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_offload_hold.h"
#include "vr_dpdk_n3k_flow.h"
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_log.h>
#include <vr_dpdk.h>
#include <time.h>

#define HELD_FLOW_TIMEOUT 10

static struct rte_hash *held_flows;

static size_t held_map_size = 0;

struct vr_n3k_offload_held_flows_key {
    uint32_t fe_index;
};

int
vr_dpdk_n3k_offload_hold_init(size_t table_size)
{
    const struct rte_hash_parameters hash_params = {
        .name = "n3k_held_flows",
        .entries = table_size,
        .key_len = sizeof(struct vr_n3k_offload_held_flows_key),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
    };

    if (held_flows) {
        rte_hash_free(held_flows);
    }

    held_flows = rte_hash_create(&hash_params);
    if (!held_flows) {
        return -rte_errno;
    }

    held_map_size = table_size;

    return 0;
}

void
vr_dpdk_n3k_offload_hold_exit()
{
    rte_hash_free(held_flows);
    held_flows = NULL;
}

static inline void
vr_dpdk_n3k_offload_hold_try_timeout() {
    struct vr_n3k_offload_held_flows_key *key = NULL;
    uint32_t *ids_to_remove = NULL;
    uint32_t remove_count = 0;
    void *entry = NULL;
    uint32_t i = 0;
    int ret;

    ids_to_remove = rte_zmalloc("n3k_offload_hold", held_map_size * sizeof(uint32_t), 0);
    if (ids_to_remove == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s() rte_zmalloc failed to allocate memory\n",
            __func__);
        return;
    }

    do {
        ret = rte_hash_iterate(held_flows, (const void **)&key, (void **)&entry, &i);
        if (ret < 0)
            break;

        time_t timestamp = (time_t)entry;
        if (timestamp + HELD_FLOW_TIMEOUT < time(NULL))
            ids_to_remove[remove_count++] = key->fe_index;

    } while(ret >= 0);

    for (i = 0; i < remove_count; i++) {
        struct vr_n3k_offload_held_flows_key del_key = {
            .fe_index = ids_to_remove[i]
        };
        RTE_LOG(WARNING, VROUTER,
            "%s() Deleting held flow with id=%d\n",
            __func__, del_key.fe_index);
        rte_hash_del_key(held_flows, &del_key);
    }

    rte_free(ids_to_remove);
}

bool
vr_dpdk_n3k_offload_hold_entry_exist(struct vr_n3k_offload_flow *flow)
{
    struct vr_n3k_offload_held_flows_key reverse_key = {
        .fe_index = flow->reverse_id
    };

    return rte_hash_lookup(held_flows, &reverse_key) >= 0;
}

bool
vr_dpdk_n3k_offload_hold_should_wait(struct vr_n3k_offload_flow *flow,
    struct vr_n3k_offload_flow *reverse_flow)
{
    struct vr_n3k_offload_flowtable_key reverse_key = {
        .fe_index = flow->reverse_id
    };

    if (flow && !reverse_flow) {
        if (!vr_dpdk_n3k_offload_flow_get(&reverse_key))
            return true;
    }

    return false;
}

bool
vr_dpdk_n3k_offload_hold_get_held(struct vr_n3k_offload_flow *flow,
    struct vr_n3k_offload_flow **reverse_flow)
{
    struct vr_n3k_offload_held_flows_key key = {
        .fe_index = flow->reverse_id
    };

    rte_hash_del_key(held_flows, &key);

    struct vr_n3k_offload_flowtable_key flow_key = {
        .fe_index = flow->reverse_id
    };

    *reverse_flow = vr_dpdk_n3k_offload_flow_get(&flow_key);
    if (!*reverse_flow) {
        RTE_LOG(WARNING, VROUTER,
            "%s() vr_dpdk_n3k_offload_flow_get failed for fe_index=%d\n",
            __func__, flow_key.fe_index);
        return false;
    }
    return true;
}

int
vr_dpdk_n3k_offload_hold_save_flow(const struct vr_n3k_offload_flow *flow)
{
    int ret;
    struct vr_n3k_offload_held_flows_key key = {
        .fe_index = flow->id
    };

    if (rte_hash_count(held_flows) >= (float)held_map_size*0.75f)
        vr_dpdk_n3k_offload_hold_try_timeout();

    if (key.fe_index == -1)
        return -EINVAL;

    ret = rte_hash_lookup(held_flows, &key);
    if (ret >= 0) {
        RTE_LOG(DEBUG, VROUTER,
            "%s(): Flow index already added to hold list(fe_index=%d)\n",
            __func__, key.fe_index);
        return 0;
    }

    RTE_LOG(DEBUG, VROUTER, "%s(): Adding fe_index to hold list(fe_index=%d)\n",
        __func__, flow->reverse_id);

    time_t timestamp = time(NULL);
    return rte_hash_add_key_data(held_flows, &key, (void*)timestamp);
}

void
vr_dpdk_n3k_offload_hold_del_flow(const struct vr_n3k_offload_flow* flow)
{
    struct vr_n3k_offload_held_flows_key key = {
        .fe_index = flow->id
    };

    rte_hash_del_key(held_flows, &key);
}
