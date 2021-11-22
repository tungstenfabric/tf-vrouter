/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_missing_mirror.h"
#include "vr_dpdk_n3k_flow.h"

static struct rte_hash *missing_mirrors;
static struct rte_hash *missing_mirror_vifs;
static struct rte_hash *missing_mirror_nexthops;

struct vr_n3k_offload_missing_mirror_flow_entry {
    uint32_t flow_id;
    struct vr_n3k_offload_missing_mirror_flow_entry *next;
};

struct vr_n3k_offload_missing_mirror_offload_key {
    uint32_t id;
};

static void
vr_dpdk_n3k_offload_missing_mirror_exit(struct rte_hash **missing_data) {
    if (*missing_data == NULL) {
        return;
    }

    struct vr_n3k_offload_missing_mirror_flow_entry *entry = NULL;
    struct vr_n3k_offload_missing_mirror_offload_key *key = NULL;
    struct vr_n3k_offload_missing_mirror_flow_entry *next = NULL;
    uint32_t i = 0;
    int ret = 0;

    do {
        ret = rte_hash_iterate(*missing_data, (const void **)&key, (void **)&entry, &i);
        if (ret < 0)
            break;

        while (entry) {
            next = entry->next;
            rte_free(entry);
            entry = next;
        }

        rte_hash_del_key(*missing_data, key);
    } while(ret >= 0);

    rte_hash_free(*missing_data);
    *missing_data = NULL;
}

static void
vr_dpdk_n3k_offload_missing_mirrors_exit() {
    vr_dpdk_n3k_offload_missing_mirror_exit(&missing_mirrors);
}

static void
vr_dpdk_n3k_offload_missing_mirror_vifs_exit() {
    vr_dpdk_n3k_offload_missing_mirror_exit(&missing_mirror_vifs);
}

static void
vr_dpdk_n3k_offload_missing_mirror_nexthops_exit() {
    vr_dpdk_n3k_offload_missing_mirror_exit(&missing_mirror_nexthops);
}

static int vr_dpdk_n3k_offload_missing_mirror_init(
    char *name, size_t table_size, struct rte_hash **missing_data)
{

    const struct rte_hash_parameters hash_params = {
        .name = name,
        .entries = table_size,
        .key_len = sizeof(struct vr_n3k_offload_missing_mirror_offload_key),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
    };

    if (*missing_data) {
        rte_hash_free(*missing_data);
    }

    *missing_data = rte_hash_create(&hash_params);
    if (!*missing_data) {
        return -rte_errno;
    }

    return 0;
}

static int
vr_dpdk_n3k_offload_missing_mirrors_init(size_t table_size)
{
    return vr_dpdk_n3k_offload_missing_mirror_init(
        "n3k_missing_mirrors", table_size,
        &missing_mirrors);
}

static int
vr_dpdk_n3k_offload_missing_mirror_vifs_init(size_t table_size)
{
    return vr_dpdk_n3k_offload_missing_mirror_init(
        "n3k_missing_vifs", table_size,
        &missing_mirror_vifs);
}

static int
vr_dpdk_n3k_offload_missing_mirror_nexthops_init(size_t table_size)
{
    return vr_dpdk_n3k_offload_missing_mirror_init(
        "n3k_missing_nexthops", table_size,
        &missing_mirror_nexthops);
}

static int
vr_dpdk_n3k_missing_mirror_map_add(struct rte_hash *hash_map, uint32_t id,
                           uint32_t flow_id)
{
    struct vr_n3k_offload_missing_mirror_flow_entry *new_entry;
    struct vr_n3k_offload_missing_mirror_flow_entry *data = NULL;
    struct vr_n3k_offload_missing_mirror_offload_key key = {
        .id = id
    };

    new_entry = (struct vr_n3k_offload_missing_mirror_flow_entry *)
        rte_zmalloc(
            "n3k_missing_mirror",
            sizeof(struct vr_n3k_offload_missing_mirror_flow_entry),
            0);
    new_entry->flow_id = flow_id;

    rte_hash_lookup_data(hash_map, &key, (void**)&data);
    new_entry->next = data;

    return rte_hash_add_key_data(hash_map, &key, new_entry);
}

int
vr_dpdk_n3k_offload_missing_mirrors_add_unlocked(uint32_t id, uint32_t flow_id) {
    return vr_dpdk_n3k_missing_mirror_map_add(missing_mirrors, id, flow_id);
}

int
vr_dpdk_n3k_offload_missing_mirror_vifs_add_unlocked(uint32_t id, uint32_t flow_id) {
    return vr_dpdk_n3k_missing_mirror_map_add(missing_mirror_vifs, id, flow_id);
}

int
vr_dpdk_n3k_offload_missing_mirror_nexthops_add_unlocked(uint32_t id, uint32_t flow_id) {
    return vr_dpdk_n3k_missing_mirror_map_add(missing_mirror_nexthops, id, flow_id);
}

static int
vr_dpdk_n3k_missing_mirror_map_lookup(
    struct rte_hash *hash_map, uint32_t id,
    struct vr_n3k_offload_missing_mirror_flow_entry **entry_head)
{
    struct vr_n3k_offload_missing_mirror_offload_key key = {
        .id = id
    };
    return rte_hash_lookup_data(hash_map, &key, (void**)entry_head);
}

static int
vr_dpdk_n3k_missing_mirror_flow_offload(uint32_t flow_id) {
    struct vr_n3k_offload_flow *flow;
    struct vr_n3k_offload_flowtable_key key;
    key.fe_index = flow_id;

    flow = vr_dpdk_n3k_offload_flow_get(&key);
    if (!flow)
        return -1;

    return vr_dpdk_n3k_offload_flow_update_unlocked(flow);
}

void
vr_dpdk_n3k_missing_mirror_offload_postponed_flows(struct rte_hash *hash_map, uint32_t id) {
    struct vr_n3k_offload_missing_mirror_flow_entry *entry_head = NULL;
    if (vr_dpdk_n3k_missing_mirror_map_lookup(hash_map, id, &entry_head) < 0)
        return;

    struct vr_n3k_offload_missing_mirror_flow_entry *entry = entry_head;
    struct vr_n3k_offload_missing_mirror_flow_entry *next = NULL;
    while (entry) {
        next = entry->next;

        vr_dpdk_n3k_missing_mirror_flow_offload(entry->flow_id);

        rte_free(entry);
        entry = next;
    }

    struct vr_n3k_offload_missing_mirror_offload_key key = {
        .id = id
    };
    rte_hash_del_key(hash_map, &key);
}

int
vr_dpdk_n3k_offload_missing_mirror_init_all(void) {
    int ret;

    ret = vr_dpdk_n3k_offload_missing_mirrors_init(128);
    if (ret)
        goto error;

    ret = vr_dpdk_n3k_offload_missing_mirror_vifs_init(128);
    if (ret)
        goto error;

    ret = vr_dpdk_n3k_offload_missing_mirror_nexthops_init(128);
    if (ret)
        goto error;

    return 0;

error:
    vr_dpdk_n3k_offload_missing_mirror_exit_all();
    return ret;
}

void
vr_dpdk_n3k_offload_missing_mirror_exit_all(void) {
    vr_dpdk_n3k_offload_missing_mirrors_exit();
    vr_dpdk_n3k_offload_missing_mirror_vifs_exit();
    vr_dpdk_n3k_offload_missing_mirror_nexthops_exit();
}

void
vr_dpdk_n3k_offload_missing_mirror_flows_unlocked(uint32_t id) {
    vr_dpdk_n3k_missing_mirror_offload_postponed_flows(missing_mirrors, id);
}

void
vr_dpdk_n3k_offload_missing_vif_flows_unlocked(uint32_t id) {
    vr_dpdk_n3k_missing_mirror_offload_postponed_flows(missing_mirror_vifs, id);
}

void
vr_dpdk_n3k_offload_missing_nexthop_flows_unlocked(uint32_t id) {
    vr_dpdk_n3k_missing_mirror_offload_postponed_flows(missing_mirror_nexthops, id);
}
