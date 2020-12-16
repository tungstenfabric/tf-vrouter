/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_packet_metadata.h"

#include <rte_byteorder.h>
#include <rte_errno.h>
#include <rte_hash.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>

#include "offload_entry/vr_dpdk_n3k_offload_entry.h"
#include "vr_dpdk_n3k_flow.h"
#include "vr_dpdk_n3k_interface.h"
#include "vr_dpdk_n3k_nexthop.h"
#include "vr_dpdk_n3k_vxlan.h"
#include "vr_dpdk_n3k_mpls.h"

#include "vr_interface.h"
#include "vr_packet.h"
#include "vr_dpdk.h"

static struct rte_hash* n3k_packets_metadata = NULL;
static rte_rwlock_t n3k_pkt_metadata_rwlock;

int
vr_dpdk_n3k_packet_metadata_init(size_t metadata_entries_count)
{
    rte_rwlock_init(&n3k_pkt_metadata_rwlock);
    rte_rwlock_write_lock(&n3k_pkt_metadata_rwlock);

    const struct rte_hash_parameters n3k_packets_metadata_params = {
        .name = "n3k_offload_packets_metadata",
        .entries = metadata_entries_count,
        .key_len = sizeof(struct vr_dpdk_n3k_packet_key),
        .extra_flag = RTE_HASH_EXTRA_FLAGS_EXT_TABLE,
    };

    n3k_packets_metadata = rte_hash_create(&n3k_packets_metadata_params);
    if (!n3k_packets_metadata) {
        rte_rwlock_write_unlock(&n3k_pkt_metadata_rwlock);
        return -rte_errno;
    }

    rte_rwlock_write_unlock(&n3k_pkt_metadata_rwlock);
    return 0;
}

int
vr_dpdk_n3k_packet_metadata_exit(void)
{
    rte_rwlock_write_lock(&n3k_pkt_metadata_rwlock);

    vr_dpdk_n3k_packet_metadata_reset();
    rte_hash_free(n3k_packets_metadata);
    n3k_packets_metadata = NULL;

    rte_rwlock_write_unlock(&n3k_pkt_metadata_rwlock);
    return 0;
}

void
vr_dpdk_n3k_packet_metadata_reset(void)
{
    struct vr_dpdk_n3k_packet_key *curr_key = NULL;
    struct vr_dpdk_n3k_packet_metadata *curr_value = NULL;
    uint32_t i = 0;
    int ret;

    do {
        ret = rte_hash_iterate(n3k_packets_metadata,
            (const void **)&curr_key, (void **)&curr_value, &i);
        if (ret >= 0)
            rte_free(curr_value);
    } while(ret >= 0);

    rte_hash_reset(n3k_packets_metadata);
}

int
vr_dpdk_n3k_packet_metadata_insert_copy(struct vr_dpdk_n3k_packet_key *key,
    struct vr_dpdk_n3k_packet_metadata *value)
{
    struct vr_dpdk_n3k_packet_metadata *metadata = NULL;
    hash_sig_t hash = rte_hash_hash(n3k_packets_metadata, key);

    rte_rwlock_write_lock(&n3k_pkt_metadata_rwlock);

    // If key is already present, copy new value and return
    int ret = rte_hash_lookup_with_hash_data(n3k_packets_metadata,
                                             key, hash, (void **)&metadata);
    if (ret >= 0) {
        rte_memcpy(metadata, value, sizeof(*metadata));
        rte_rwlock_write_unlock(&n3k_pkt_metadata_rwlock);
        return 0;
    }

    metadata = rte_zmalloc("pkt_metadata", sizeof(*metadata), 0);
    if (metadata == NULL) {
        RTE_LOG(ERR, VROUTER, "%s(): Allocation failed\n", __func__);
        rte_rwlock_write_unlock(&n3k_pkt_metadata_rwlock);
        return -ENOMEM;
    }

    rte_memcpy(metadata, value, sizeof(*metadata));

    ret = rte_hash_add_key_with_hash_data(n3k_packets_metadata, key, hash, metadata);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Cannot save packet metadata. Error: %d\n", __func__, ret);
        rte_free(metadata);
    }

    rte_rwlock_write_unlock(&n3k_pkt_metadata_rwlock);
    return ret;
}

int
vr_dpdk_n3k_packet_metadata_delete(struct vr_dpdk_n3k_packet_key *key)
{
    struct vr_dpdk_n3k_packet_metadata *value = NULL;
    hash_sig_t hash = rte_hash_hash(n3k_packets_metadata, key);

    rte_rwlock_write_lock(&n3k_pkt_metadata_rwlock);

    rte_hash_lookup_with_hash_data(
        n3k_packets_metadata, key, hash, (void **)&value);

    int ret = rte_hash_del_key_with_hash(n3k_packets_metadata, key, hash);

    rte_rwlock_write_unlock(&n3k_pkt_metadata_rwlock);

    rte_free(value);

    return ret;
}

static int
vr_dpdk_n3k_packet_metadata_find(struct vr_dpdk_n3k_packet_key *key,
    struct vr_dpdk_n3k_packet_metadata *out_value)
{
    struct vr_dpdk_n3k_packet_metadata *out = NULL;

    rte_rwlock_read_lock(&n3k_pkt_metadata_rwlock);
    int ret = rte_hash_lookup_data(n3k_packets_metadata, key, (void **)&out);
    if (ret >= 0) {
        *out_value = *out;
    }
    rte_rwlock_read_unlock(&n3k_pkt_metadata_rwlock);

    return ret < 0 ? ret : 0;
}

int
vr_dpdk_n3k_packet_metadata_find_by_flow(
    const struct vr_n3k_offload_flow *flow,
    struct vr_dpdk_n3k_packet_metadata *out_value)
{
    struct vr_dpdk_n3k_packet_key key;
    vr_dpdk_n3k_packet_metadata_fill_key_from_flow(flow, &key);
    return vr_dpdk_n3k_packet_metadata_find(&key, out_value);
}

void
vr_dpdk_n3k_packet_metadata_fill_key_from_flow(
    const struct vr_n3k_offload_flow *flow,
    struct vr_dpdk_n3k_packet_key *key)
{
    memset(key, 0, sizeof(*key));

    key->nh_id = flow->nh_id;
    key->src_ip = flow->src_ip;
    key->dst_ip = flow->dst_ip;
    key->proto = flow->proto;
    key->src_port = flow->src_port;
    key->dst_port = flow->dst_port;
}

static inline int
vr_dpdk_n3k_packet_metadata_fill_vm_rx_value_from_offload_entry(
    const struct vr_n3k_offload_entry *entry,
    struct vr_dpdk_n3k_packet_metadata *value)
{
    const uint8_t *src_mac = NULL;
    const uint8_t *dst_mac = NULL;

    if (entry->route_traffic) {
        src_mac = entry->dst_nh->dst_mac;
        dst_mac = entry->dst_nh->src_mac;
    } else {
        if (entry->pkt_metadata.eth_hdr_present) {
            src_mac = entry->pkt_metadata.inner_dst_mac;
            dst_mac = entry->pkt_metadata.inner_src_mac;
        } else {
            struct vr_n3k_offload_mpls *offload_mpls =
                vr_dpdk_n3k_offload_mpls_get_by_label(
                    entry->tunnel_label);

            struct vr_n3k_offload_nexthop *offload_nexthop = offload_mpls ?
                vr_dpdk_n3k_offload_nexthop_get(offload_mpls->nexthop_id) : NULL;

            if (offload_nexthop) {
                src_mac = offload_nexthop->dst_mac;
                dst_mac = offload_nexthop->src_mac;
            } else {
                return -EINVAL;
            }
        }
    }

    value->eth_hdr_present = true;
    memcpy(value->inner_src_mac, src_mac, VR_ETHER_ALEN);
    memcpy(value->inner_dst_mac, dst_mac, VR_ETHER_ALEN);

    return 0;
}

static inline int
vr_dpdk_n3k_packet_metadata_fill_fabric_rx_value_from_offload_entry(
    const struct vr_n3k_offload_entry *entry,
    struct vr_dpdk_n3k_packet_metadata *value)
{
    value->eth_hdr_present = false;

    if (!entry->route_traffic) {
        value->eth_hdr_present = true;
        memcpy(value->inner_src_mac,
            entry->pkt_metadata.inner_dst_mac,
            VR_ETHER_ALEN);
        memcpy(value->inner_dst_mac,
            entry->pkt_metadata.inner_src_mac,
            VR_ETHER_ALEN);
    }

    return 0;
}

static inline int
vr_dpdk_n3k_packet_metadata_fill_value_from_offload_entry(
    const struct vr_n3k_offload_entry *entry,
    struct vr_dpdk_n3k_packet_metadata *metadata)
{
    int ret;

    if (entry->dst_vif->type == VIF_TYPE_VIRTUAL) {
        if ((ret = vr_dpdk_n3k_packet_metadata_fill_vm_rx_value_from_offload_entry(
                 entry, metadata)) < 0) {
            return ret;
        }

        return 0;
    }

    if (entry->dst_vif->type == VIF_TYPE_PHYSICAL) {
        if ((ret = vr_dpdk_n3k_packet_metadata_fill_fabric_rx_value_from_offload_entry(
                 entry, metadata)) < 0) {
            return ret;
        }

        return 0;
    }

    return -EINVAL;
}

static int
vr_dpdk_n3k_packet_metadata_insert_from_offload_entry(
    const struct vr_n3k_offload_entry *entry)
{
    int ret;
    struct vr_dpdk_n3k_packet_key key;
    vr_dpdk_n3k_packet_metadata_fill_key_from_flow(entry->reverse_flow, &key);

    struct vr_dpdk_n3k_packet_metadata value;
    if ((ret = vr_dpdk_n3k_packet_metadata_fill_value_from_offload_entry(entry, &value)) < 0)
        return ret;

    return vr_dpdk_n3k_packet_metadata_insert_copy(&key, &value);
}

int
vr_dpdk_n3k_packet_metadata_ensure_entry_for_flow_exists(
    struct vr_n3k_offload_flow *flow,
    struct vr_n3k_offload_flow *reverse_flow)
{
    struct vr_dpdk_n3k_packet_metadata metadata;
    if (vr_dpdk_n3k_packet_metadata_find_by_flow(flow, &metadata) >= 0)
        return 0;

    if (reverse_flow == NULL) {
        RTE_LOG(ERR, VROUTER, "%s(): Reverse flow is NULL for flow %d\n",
            __func__, flow->id);
        return -EINVAL;
    }

    struct vr_n3k_offload_entry reverse_offload_entry;
    int ret = vr_dpdk_n3k_fill_offload_entry(
        reverse_flow, &reverse_offload_entry);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Cannot create offload_entry for reverse flow %d: %d\n",
            __func__, reverse_flow->id, ret);
        return ret;
    }

    ret = vr_dpdk_n3k_packet_metadata_insert_from_offload_entry(
        &reverse_offload_entry);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Failed to insert metadata for reverse flow %d: %d\n",
            __func__, reverse_flow->id, ret);
        return ret;
    }

    return 0;
}
