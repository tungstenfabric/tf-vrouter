/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_routes.h"

#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_lpm.h>
#include <rte_ring.h>

#include "vr_dpdk.h"
#include "vr_types.h"

#define VR_DPDK_N3K_ROUTE_TABLE_SIZE 65536

struct vr_dpdk_n3k_route_data {
    struct rte_lpm *table;
    struct rte_ring *free_entries;
    struct vr_n3k_offload_route_value entries[VR_DPDK_N3K_ROUTE_TABLE_SIZE];
};

struct vr_dpdk_n3k_route_vrfs_data {
    size_t count;
    struct vr_dpdk_n3k_route_data *data[0];
};

static struct rte_hash* n3k_bridge_data = NULL;
struct vr_dpdk_n3k_route_vrfs_data *n3k_route_data = NULL;

static const struct rte_lpm_config vr_dpdk_n3k_route_table_params = {
    .max_rules = VR_DPDK_N3K_ROUTE_TABLE_SIZE,
    .number_tbl8s = RTE_LPM_TBL8_GROUP_NUM_ENTRIES,
    .flags = -1, //not used
};

static struct rte_hash_parameters vr_dpdk_n3k_bridge_hash_params = {
    .name = "vr_dpdk_n3k_bridgehash",
    .key_len = sizeof(struct vr_n3k_offload_bridge_key),
    .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
};

static inline uint32_t
get_ip(vr_route_req *req)
{
    uint32_t ip;
    assert(sizeof(ip) == req->rtr_prefix_size);

    memcpy(&ip, req->rtr_prefix, sizeof(ip));
    return ip;
}

static int
ensure_route_data_is_initialized(uint32_t vrf)
{
    int ret;
    uintptr_t idx;

    if (n3k_route_data->data[vrf])
        return 0;

    char lpm_name[RTE_LPM_NAMESIZE];
    ret = snprintf(lpm_name, RTE_LPM_NAMESIZE, "n3k_rt_lpm_vrf%u", vrf);
    if (ret < 0 || ret > RTE_LPM_NAMESIZE)
        return -EINVAL;

    char ring_name[RTE_RING_NAMESIZE];
    ret = snprintf(ring_name, RTE_RING_NAMESIZE, "n3k_rt_ring_vrf%u", vrf);
    if (ret < 0 || ret > RTE_RING_NAMESIZE)
        return -EINVAL;

    struct vr_dpdk_n3k_route_data *data =
        rte_zmalloc("n3k_offload_routing", sizeof(*data), 0);
    if (!data)
        return -ENOMEM;

    data->table = rte_lpm_create(lpm_name, 0, &vr_dpdk_n3k_route_table_params);
    if (!data->table) {
        ret = -rte_errno;
        goto free_data;
    }

    data->free_entries = rte_ring_create(
        ring_name, VR_DPDK_N3K_ROUTE_TABLE_SIZE, 0,
        RING_F_EXACT_SZ | RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!data->free_entries) {
        ret = -rte_errno;
        goto free_lpm;
    }

    for (idx = 0; idx < VR_DPDK_N3K_ROUTE_TABLE_SIZE; ++idx) {
        ret = rte_ring_sp_enqueue(data->free_entries, (void *)idx);
        if (ret)
            goto free_ring;
    }

    n3k_route_data->data[vrf] = data;

    return 0;

free_ring:
    rte_ring_free(data->free_entries);

free_lpm:
    rte_lpm_free(data->table);

free_data:
    rte_free(data);

    return ret;
}

static void
free_route_tables(void)
{
    int i;

    for (i = 0; i < n3k_route_data->count; ++i) {
        struct vr_dpdk_n3k_route_data *data = n3k_route_data->data[i];

        if (data) {
            rte_ring_free(data->free_entries);
            rte_lpm_free(data->table);
            n3k_route_data->data[i] = NULL;
        }
    }
}

int
vr_dpdk_n3k_offload_bridge_add_internal(
    struct vr_n3k_offload_bridge_key *key,
    struct vr_n3k_offload_bridge_value *value)
{
    /* Cannot cast directly because of strict-aliasing rules */
    uintptr_t value_buffer;
    assert(sizeof(*value) == sizeof(uintptr_t));
    memcpy(&value_buffer, value, sizeof(*value));

    int ret = rte_hash_add_key_data(n3k_bridge_data, key, (void *)value_buffer);
    if (ret < 0)
        return ret;

    return 0;
}

static int
vr_dpdk_n3k_offload_bridge_del_internal(
    struct vr_n3k_offload_bridge_key *key)
{
    /* We don't have to free the value because it's stored as 8-byte value */
    int ret = rte_hash_del_key(n3k_bridge_data, key);
    if (ret < 0)
        return ret;

    return 0;
}

int
vr_dpdk_n3k_offload_route_add_internal(
    uint32_t vrf, uint32_t ip, uint8_t prefix_len,
    struct vr_n3k_offload_route_value *value)
{
    int ret;
    uintptr_t index;

    if (vrf > n3k_route_data->count)
        return -EINVAL;

    ret = ensure_route_data_is_initialized(vrf);
    if (ret)
        return ret;

    struct vr_dpdk_n3k_route_data *data = n3k_route_data->data[vrf];

    ret = rte_ring_sc_dequeue(data->free_entries, (void **)&index);
    if (ret)
        return ret;

    assert(index < VR_DPDK_N3K_ROUTE_TABLE_SIZE);
    data->entries[index] = *value;

    ret = rte_lpm_add(data->table, rte_be_to_cpu_32(ip), prefix_len, index);
    if (ret) {
        rte_ring_sp_enqueue(data->free_entries, (void *)index);
        return ret;
    }

    return 0;
}

static int
vr_dpdk_n3k_offload_route_del_internal(
    uint32_t vrf, uint32_t ip, uint8_t prefix_len)
{
    int ret;
    uint32_t index;
    uintptr_t index_data;

    if (vrf > n3k_route_data->count)
        return -EINVAL;

    struct vr_dpdk_n3k_route_data *data = n3k_route_data->data[vrf];
    if (data == NULL)
        return -ENOENT;

    ret = rte_lpm_is_rule_present(
        data->table, rte_be_to_cpu_32(ip), prefix_len, &index);
    if (ret != 1)
        return -ENOENT;

    ret = rte_lpm_delete(data->table, rte_be_to_cpu_32(ip), prefix_len);
    if (ret)
        return ret;

    index_data = index;
    ret = rte_ring_sp_enqueue(data->free_entries, (void *)index_data);
    if (ret)
        return ret;

    return 0;
}

int
vr_dpdk_n3k_offload_routing_add(vr_route_req *req)
{
    if (req->rtr_family == AF_BRIDGE) {
        RTE_LOG(
            DEBUG, VROUTER,
            "%s() called; family=AF_BRIDGE; vrf=%d; mac=" MAC_FORMAT "; nh=%d; vni=%d;\n",
            __func__, req->rtr_vrf_id,
            MAC_VALUE((const uint8_t *)req->rtr_mac),
            req->rtr_nh_id, req->rtr_label
        );

        struct vr_n3k_offload_bridge_key key;
        memset(&key, 0, sizeof(key));
        key.vrf_id = req->rtr_vrf_id;
        memcpy(&key.mac, req->rtr_mac, VR_ETHER_ALEN);

        struct vr_n3k_offload_bridge_value value = {
            req->rtr_label, req->rtr_nh_id
        };

        return vr_dpdk_n3k_offload_bridge_add_internal(&key, &value);
    } else if (req->rtr_family == AF_INET) {
        RTE_LOG(
            DEBUG, VROUTER,
            "%s() called; family=AF_INET; vrf=%d; ip=" IPV4_FORMAT "/%d; nh=%d; label=%d;\n",
            __func__, req->rtr_vrf_id, IPV4_VALUE(req->rtr_prefix), req->rtr_prefix_len,
            req->rtr_nh_id, req->rtr_label
        );

        uint32_t ip = get_ip(req);

        if (req->rtr_nh_id < 0)
            return -EINVAL;

        if (req->rtr_prefix_len < 0 || req->rtr_prefix_len > 32)
            return -EINVAL;

        struct vr_n3k_offload_route_value value = {
            req->rtr_label, req->rtr_nh_id
        };

        return vr_dpdk_n3k_offload_route_add_internal(
            req->rtr_vrf_id, ip, req->rtr_prefix_len, &value);
    }

    return -EINVAL;
}

int
vr_dpdk_n3k_offload_routing_del(vr_route_req *req)
{
    if (req->rtr_family == AF_BRIDGE) {
        RTE_LOG(
            DEBUG, VROUTER,
            "%s() called; family=AF_BRIDGE; vrf=%d; mac=" MAC_FORMAT ";\n",
            __func__, req->rtr_vrf_id, MAC_VALUE((const uint8_t *)req->rtr_mac)
        );

        struct vr_n3k_offload_bridge_key key;
        memset(&key, 0, sizeof(key));
        key.vrf_id = req->rtr_vrf_id;
        memcpy(&key.mac, req->rtr_mac, VR_ETHER_ALEN);

        return vr_dpdk_n3k_offload_bridge_del_internal(&key);
    } else if (req->rtr_family == AF_INET) {
        RTE_LOG(
            DEBUG, VROUTER,
            "%s() called; family=AF_INET; vrf=%d; ip=" IPV4_FORMAT ";\n",
            __func__, req->rtr_vrf_id, IPV4_VALUE(req->rtr_prefix)
        );

        uint32_t ip = get_ip(req);

        if (req->rtr_prefix_len < 0 || req->rtr_prefix_len > 32)
            return -EINVAL;

        return vr_dpdk_n3k_offload_route_del_internal(
            req->rtr_vrf_id, ip, (uint8_t)req->rtr_prefix_len);
    }

    return -EINVAL;
}

int
vr_dpdk_n3k_offload_routing_init(
    int bridge_entries, unsigned int max_vrf_count)
{
    //Updated, hash tables work well on sparse arrays (collisions)
    vr_dpdk_n3k_bridge_hash_params.entries = 2 * bridge_entries;
    n3k_bridge_data = rte_hash_create(&vr_dpdk_n3k_bridge_hash_params);
    if (n3k_bridge_data == NULL)
        return -rte_errno;

    size_t route_data_size =
        sizeof(struct vr_dpdk_n3k_route_vrfs_data) +
        max_vrf_count * sizeof(struct vr_dpdk_n3k_route_data *);
    n3k_route_data = rte_zmalloc("n3k_routing", route_data_size, 0);
    if (!n3k_route_data) {
        rte_hash_free(n3k_bridge_data);
        n3k_bridge_data = NULL;
        return -ENOMEM;
    }

    n3k_route_data->count = max_vrf_count;

    return 0;
}

int
vr_dpdk_n3k_offload_routing_exit(void)
{
    vr_dpdk_n3k_offload_routing_reset();

    if (n3k_bridge_data != NULL) {
        rte_hash_free(n3k_bridge_data);
        n3k_bridge_data = NULL;
    }

    if (n3k_route_data != NULL) {
        rte_free(n3k_route_data);
        n3k_route_data = NULL;
    }

    return 0;
}

int
vr_dpdk_n3k_offload_routing_reset(void)
{
    free_route_tables();
    rte_hash_reset(n3k_bridge_data);

    return 0;
}

int
vr_dpdk_n3k_offload_route_find(struct vr_n3k_offload_route_key *key,
    struct vr_n3k_offload_route_value *out_value)
{
    int ret;
    uint32_t index;

    if (key->vrf_id > n3k_route_data->count)
        return -EINVAL;

    struct vr_dpdk_n3k_route_data *data = n3k_route_data->data[key->vrf_id];
    if (!data)
        return -ENOENT;

    ret = rte_lpm_lookup(data->table, rte_be_to_cpu_32(key->ip), &index);
    if (ret) {
        return ret;
    }

    *out_value = data->entries[index];

    return 0;
}

int
vr_dpdk_n3k_offload_bridge_find(
    struct vr_n3k_offload_bridge_key *key,
    struct vr_n3k_offload_bridge_value *out_value)
{
    return rte_hash_lookup_data(n3k_bridge_data, key, (void **)out_value);
}
