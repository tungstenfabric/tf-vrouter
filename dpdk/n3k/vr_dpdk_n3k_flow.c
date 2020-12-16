/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */
#include "vr_dpdk_n3k_flow.h"

#include <rte_hash.h>
#include <rte_log.h>
#include <rte_malloc.h>

#include "offload_entry/vr_dpdk_n3k_offload_converter.h"
#include "offload_entry/vr_dpdk_n3k_offload_entry.h"
#include "vr_dpdk_n3k_packet_metadata.h"
#include "vr_dpdk_n3k_interface.h"
#include "vr_dpdk_n3k_offload_hold.h"

#include "vr_dpdk.h"

/* TODO(n3k): Refactor this */
unsigned int disable_drop_offloads = 0;

static uint32_t flows_count;
static struct vr_n3k_offload_flow **flows = NULL;

int
vr_dpdk_n3k_offload_flow_table_add(
    struct vr_n3k_offload_flowtable_key *key,
    struct vr_n3k_offload_flow *flow)
{
    if (!flows || key->fe_index >= flows_count)
        return -EINVAL;

    flows[key->fe_index] = flow;
    return 0;
}

static int
vr_dpdk_n3k_offload_flow_table_del(struct vr_n3k_offload_flowtable_key *key)
{
    if (!flows || key->fe_index >= flows_count)
        return -EINVAL;

    rte_free(flows[key->fe_index]);
    flows[key->fe_index] = NULL;
    return 0;
}

static inline void
vr_dpdk_n3k_offload_flow_del_internal(struct vr_n3k_offload_flow *fe);

static int
vr_dpdk_n3k_offload_correct_missing_rfe_index(struct vr_flow_entry *fe,
    struct vr_n3k_offload_flow *oflow)
{
    int ret;
    struct vr_n3k_offload_flow *old_rfe;
    struct vr_n3k_offload_flow new_rfe;
    uint32_t old_rfe_id = oflow->reverse_id;
    struct vr_n3k_offload_flowtable_key old_key = {
        .fe_index = oflow->reverse_id
    };
    struct vr_n3k_offload_flowtable_key new_key = {
        .fe_index = fe->fe_rflow
    };

    oflow->reverse_id = fe->fe_rflow;

    if (old_rfe_id == 0 || old_rfe_id == fe->fe_rflow)
        return 0;

    RTE_LOG(WARNING, VROUTER, "%s(): rfe_index changed from %d to %d\n",
        __func__, old_rfe_id, fe->fe_rflow);

    old_rfe = vr_dpdk_n3k_offload_flow_get(&old_key);
    if (!old_rfe) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Failed to get old rfe; fe_index: %d\n", __func__,
            old_key.fe_index);
        return -ENOENT;
    }

    memcpy(&new_rfe, old_rfe, sizeof(struct vr_n3k_offload_flow));
    new_rfe.id = new_key.fe_index;

    /* Updating flow table */
    ret = vr_dpdk_n3k_offload_flow_table_del(&old_key);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Failed to remove old flow; fe_index: %d\n", __func__,
            old_key.fe_index);
        return ret;
    }

    struct vr_n3k_offload_flow *flow = vr_dpdk_n3k_offload_flow_get(&new_key);
    if (flow == NULL) {
        flow = rte_zmalloc("n3k_flow", sizeof(*flow), 0);
        if (flow == NULL) {
            RTE_LOG(ERR, VROUTER,
                "%s(): Insufficient memory for flow allocation.\n", __func__);
            ret = -ENOMEM;
            goto flow_del;
        }
    }

    memcpy(flow, &new_rfe, sizeof(struct vr_n3k_offload_flow));

    ret = vr_dpdk_n3k_offload_flow_table_add(&new_key, flow);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): vr_dpdk_n3k_offload_flow_table_add failed: ret = %d;\n",
            __func__, ret);
        rte_free(flow);
        goto flow_del;
    }
    return 0;

flow_del:
    vr_dpdk_n3k_offload_flow_del_internal(&new_rfe);
    return ret;
}

static inline void
vr_dpdk_n3k_offload_flow_construct(
    struct vr_flow_entry *fe,
    struct vr_flow_entry *rfe,
    struct vr_n3k_offload_flow *oflow)
{
    oflow->id = fe->fe_hentry.hentry_index;
    oflow->action = fe->fe_action;
    oflow->flags = fe->fe_flags;
    oflow->tcp_flags = fe->fe_tcp_flags;
    oflow->src_ip = fe->fe_key.flow4_sip;
    oflow->dst_ip = fe->fe_key.flow4_dip;
    oflow->proto = fe->fe_key.flow4_proto;
    oflow->src_port = fe->fe_key.flow4_sport;
    oflow->dst_port = fe->fe_key.flow4_dport;
    oflow->tunnel_udp_src_port = RTE_BE16(fe->fe_udp_src_port);
    oflow->nh_id = fe->fe_key.flow_nh_id;
    oflow->src_vrf_id = fe->fe_vrf;
    oflow->ecmp_nh_idx = fe->fe_ecmp_nh_index;

    // There is a flag in vr_flow_entry to determine if mirroring is enabled.
    // At the same time VR_MAX_MIRROR_INDICES is an invalid value that
    // fits into uint8_t, so the flag seems to be redundant.
    // VR_MAX_MIRROR_INDICES is used in vrouter to initialize mirroring id
    // when mirroring is disabled.
    // To keep consistency with vouter code, the flag is checked here;
    // further in the processing VR_MAX_MIRROR_INDICES is used
    // to mark that mirroring is disabled.
    // Only one vif is currently supported in offloading procedure, so
    // secondary mirroring id (present in vr_flow_entry) is currently ignored.
    // TODO: decide if fe_sec_mirror_id requires further attention.
    if (fe->fe_flags & VR_FLOW_FLAG_MIRROR) {
        oflow->mirror_id = fe->fe_mirror_id;
    } else {
        oflow->mirror_id = VR_MAX_MIRROR_INDICES;
    }

    if (rfe != NULL)
        oflow->reverse_id = rfe->fe_hentry.hentry_index;
}

static inline struct vr_n3k_offload_flowtable_key
vr_dpdk_n3k_offload_flow_key_construct(struct vr_flow_entry *fe)
{
    struct vr_n3k_offload_flowtable_key key = {
        .fe_index = fe->fe_hentry.hentry_index
    };

    return key;
}

static void
vr_dpdk_n3k_flow_discard_all_flows(void)
{
    uint32_t i = 0;

    for (i = 0; i < flows_count; ++i) {
        rte_free(flows[i]);
        flows[i] = NULL;
    }
}

struct vr_n3k_offload_flow *
vr_dpdk_n3k_offload_flow_get(struct vr_n3k_offload_flowtable_key *key)
{
    if (!flows || key->fe_index >= flows_count)
        return NULL;

    return flows[key->fe_index];
}

int
vr_dpdk_n3k_offload_flow_init(size_t flowtable_sz)
{
    if (flows) {
        vr_dpdk_n3k_flow_discard_all_flows();
        rte_free(flows);
        flows = NULL;
    }

    flows = rte_zmalloc("n3k_offload_flow", flowtable_sz * sizeof(*flows), 0);
    if (flows == NULL)
        return -ENOMEM;

    flows_count = flowtable_sz;

    return 0;
}

void
vr_dpdk_n3k_offload_flow_exit(void)
{
    vr_dpdk_n3k_flow_discard_all_flows();
    rte_free(flows);
    flows = NULL;
}

static struct vr_n3k_offload_flow *
vr_dpdk_n3k_offload_flow_save_copy(
    struct vr_flow_entry *fe, struct vr_flow_entry *rfe)
{
    struct vr_n3k_offload_flowtable_key key =
        vr_dpdk_n3k_offload_flow_key_construct(fe);

    struct vr_n3k_offload_flow *oflow = vr_dpdk_n3k_offload_flow_get(&key);
    if (oflow == NULL) {
        oflow = rte_zmalloc("n3k_flow", sizeof(*oflow), 0);
        if (oflow == NULL) {
            RTE_LOG(ERR, VROUTER,
                "%s(): Insufficient memory for flow allocation.\n", __func__);
            return NULL;
        }
    }

    vr_dpdk_n3k_offload_flow_construct(fe, rfe, oflow);

    if (vr_dpdk_n3k_offload_flow_table_add(&key, oflow)) {
        rte_free(oflow);
        return NULL;
    }

    return oflow;
}

static inline void
log_flow_details(struct vr_flow_entry *fe, const char *prefix)
{
    RTE_LOG(DEBUG, VROUTER,
        "%10s: id=%d; action=%d; flags=%#x; nh=%d; vrf=%d; rflow=%d;\n",
        prefix, fe->fe_hentry.hentry_index, fe->fe_action, fe->fe_flags,
        fe->fe_key.flow_nh_id, fe->fe_vrf, fe->fe_rflow
    );

    RTE_LOG(DEBUG, VROUTER,
        "            sip=" IPV4_FORMAT "; dip=" IPV4_FORMAT "; "
        "proto=%d; sport=%d; dport=%d;\n",
        IPV4_VALUE(&fe->fe_key.flow4_sip),
        IPV4_VALUE(&fe->fe_key.flow4_dip),
        fe->fe_key.flow4_proto,
        rte_be_to_cpu_16(fe->fe_key.flow4_sport),
        rte_be_to_cpu_16(fe->fe_key.flow4_dport)
    );
}

static int
vr_dpdk_n3k_offload_destroy_hw_flow(
    struct rte_flow *handle, uint16_t port_id, uint32_t flow_idx)
{
    struct rte_flow_error error = { 0 };
    int ret = rte_flow_destroy(port_id, handle, &error);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Failed to destroy hardware flow %d: ret = %d; [%d]: %s\n",
            __func__, flow_idx, ret, error.type, error.message ?
                error.message : "No error message");
    }

    return ret;
}

static inline void
vr_dpdk_n3k_offload_flow_del_internal(struct vr_n3k_offload_flow *fe) {
    if (fe->handle != NULL) {
        vr_dpdk_n3k_offload_destroy_hw_flow(
            fe->handle, fe->hw_port_id, fe->id);
        fe->handle = NULL;
    }
    struct vr_dpdk_n3k_packet_key pkt_metadata_key;
    vr_dpdk_n3k_packet_metadata_fill_key_from_flow(fe, &pkt_metadata_key);
    vr_dpdk_n3k_packet_metadata_delete(&pkt_metadata_key);
}

static inline bool
vr_dpdk_n3k_offload_flow_is_tcp_not_established(const struct vr_n3k_offload_flow *flow)
{
    if (flow->proto != VR_IP_PROTO_TCP)
        return false;

    if (flow->tcp_flags & VR_FLOW_TCP_ESTABLISHED)
        return false;

    if (flow->tcp_flags & VR_FLOW_TCP_ESTABLISHED_R)
        return false;

    return true;
}

static inline bool
vr_dpdk_n3k_offload_flow_is_offloadable_proto(const struct vr_n3k_offload_flow *flow)
{
    if (flow->proto == VR_IP_PROTO_TCP) {
        if (flow->action == VR_FLOW_ACTION_DROP)
            return true;

        return !vr_dpdk_n3k_offload_flow_is_tcp_not_established(flow);
    } else if (flow->proto== VR_IP_PROTO_UDP) {
        return true;
    } else {
        return false;
    }
}


static int
vr_dpdk_n3k_offload_flow_set_internal(
    struct vr_n3k_offload_flow *flow,
    uint32_t fe_index,
    struct vr_n3k_offload_flow *reverse_flow)
{
    if (flow->handle != NULL) {
        vr_dpdk_n3k_offload_destroy_hw_flow(
            flow->handle, flow->hw_port_id, fe_index);
        flow->handle = NULL;
    }

    int ret = vr_dpdk_n3k_packet_metadata_ensure_entry_for_flow_exists(
        flow, reverse_flow);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): Cannot rebuild packet metadata for flow %d: %d\n",
            __func__, flow->id, ret);
        return ret;
    }

    if (disable_drop_offloads && flow->action == VR_FLOW_ACTION_DROP) {
        RTE_LOG(DEBUG, VROUTER,
            "%s(): Skipping offload: DROP packets go to slowpath\n", __func__);
        return 0;
    }

    if (!vr_dpdk_n3k_offload_flow_is_offloadable_proto(flow)) {
        /* We do not offload tcp handshakes, only data. Skip. */
        RTE_LOG(DEBUG, VROUTER,
            "%s(): Skipping offload: proto not offloadable\n", __func__);
        return 0;
    }

    struct vr_n3k_offload_entry offload_entry;
    ret = vr_dpdk_n3k_fill_offload_entry(flow, &offload_entry);
    if (ret) {
        RTE_LOG(ERR, VROUTER, "%s(): vr_dpdk_n3k_fill_offload_entry failed: %d\n",
            __func__, ret);
        return ret;
    }

    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(&offload_entry);
    if (flow_package.error) {
        RTE_LOG(ERR, VROUTER,
            "%s(): vr_dpdk_n3k_offload_entry_to_rte_flow failed: %d\n",
            __func__, flow_package.error);
        return flow_package.error;
    }

    flow->hw_port_id = offload_entry.src_vif->port_id;

    struct rte_flow_error error;
    static struct rte_flow_attr attr = {
        .ingress = 1,
    };

    flow->handle = rte_flow_create(
        flow->hw_port_id,
        &attr,
        flow_package.pattern,
        flow_package.actions,
        &error
    );

    if (flow->handle == NULL) {
        RTE_LOG(ERR, VROUTER, "%s(): Failed to create flow %d: [%d]: %s\n",
            __func__, fe_index, error.type, error.message ?
                error.message : "No error message");
        return -EINVAL;
    }

    return 0;
}

int
vr_dpdk_n3k_offload_flow_set(struct vr_flow_entry *fe, uint32_t fe_index,
    struct vr_flow_entry *rfe)
{
    int ret;
    RTE_LOG(DEBUG, VROUTER, "%s() called; fe=%p; fe_index=%u; rfe=%p\n",
        __func__, fe, fe_index, rfe);
    log_flow_details(fe, "fe");
    if (rfe != NULL)
        log_flow_details(rfe, "rfe");

    struct vr_n3k_offload_flow *reverse_flow = NULL;
    struct vr_n3k_offload_flow *flow =
        vr_dpdk_n3k_offload_flow_save_copy(fe, rfe);
    if (flow == NULL)
        return -ENOMEM;

    /* TODO(n3k): Should we handle error here? */
    if (rfe != NULL)
        reverse_flow = vr_dpdk_n3k_offload_flow_save_copy(rfe, fe);
    else {
        ret = vr_dpdk_n3k_offload_correct_missing_rfe_index(fe, flow);
        if (ret < 0)
            RTE_LOG(ERR, VROUTER,
                "%s() vr_dpdk_n3k_offload_correct_missing_rfe_index failed "
                "with error ret=%d; fe=%p; fe_index=%u; rfe=%p\n",
                __func__, ret, fe, fe_index, rfe);
    }

    bool hold_entry_exist = vr_dpdk_n3k_offload_hold_entry_exist(flow);
    if (!hold_entry_exist && vr_dpdk_n3k_offload_hold_should_wait(flow, reverse_flow)) {
        ret = vr_dpdk_n3k_offload_hold_save_flow(flow);
        if (ret < 0) {
            RTE_LOG(ERR, VROUTER,
                "%s() vr_dpdk_n3k_offload_hold_save_flow failed for fe_index=%d; ret=%d\n",
                __func__,
                flow->reverse_id, ret);
        }
        return 0;
    }
    else if(hold_entry_exist && vr_dpdk_n3k_offload_hold_get_held(flow, &reverse_flow)) {
        RTE_LOG(WARNING, VROUTER,
            "%s() Offloading held flows fe_index=%d; rfe_index=%d\n",
            __func__, flow->reverse_id, flow->id);

        ret = vr_dpdk_n3k_offload_flow_set_internal(reverse_flow, flow->reverse_id, flow);
        if (ret < 0) {
            RTE_LOG(ERR,
                VROUTER,
                "%s() vr_dpdk_n3k_offload_flow_set_internal(fe=%d, "
                "rfe=%d) failed with ret=%d\n",
                __func__,
                reverse_flow->id, flow->id, ret);
            return ret;
        }
    }

    return vr_dpdk_n3k_offload_flow_set_internal(flow, fe_index, reverse_flow);
}

int
vr_dpdk_n3k_offload_flow_del(struct vr_flow_entry *fe)
{
    struct vr_n3k_offload_flowtable_key ftable_key;
    struct vr_n3k_offload_flow* flow;

    RTE_LOG(DEBUG, VROUTER, "%s() called; fe=%p\n", __func__, fe);
    log_flow_details(fe, "fe");

    ftable_key = vr_dpdk_n3k_offload_flow_key_construct(fe);
    flow = vr_dpdk_n3k_offload_flow_get(&ftable_key);
    if (flow == NULL)
        return -ENOENT;

    vr_dpdk_n3k_offload_hold_del_flow(flow);

    vr_dpdk_n3k_offload_flow_del_internal(flow);

    vr_dpdk_n3k_offload_flow_table_del(&ftable_key);

    return 0;
}

int
vr_dpdk_n3k_offload_flow_stats_update(struct vr_flow_entry *fe)
{
    struct vr_n3k_offload_flowtable_key ftable_key;
    struct vr_n3k_offload_flow* flow;

    RTE_LOG(DEBUG, VROUTER, "%s() called; fe=%p\n", __func__, fe);
    log_flow_details(fe, "fe");

    ftable_key = vr_dpdk_n3k_offload_flow_key_construct(fe);
    flow = vr_dpdk_n3k_offload_flow_get(&ftable_key);
    if (flow == NULL || flow->handle == NULL) {
        RTE_LOG(DEBUG, VROUTER, "%s(): Flow is not offloaded\n", __func__);
        return -ENOENT;
    }

    struct rte_flow_query_count query = {0};
    query.hits_set = 1;
    query.bytes_set = 1;

    struct rte_flow_error error = {0};
    struct rte_flow_action actions[] = {
        [0] = {
            .type = RTE_FLOW_ACTION_TYPE_COUNT,
            .conf = NULL,
        },
        [1] = {
            .type = RTE_FLOW_ACTION_TYPE_END,
            .conf = NULL,
        },
    };

    int ret = rte_flow_query(flow->hw_port_id, flow->handle,
        actions, &query, &error);

    if (ret != 0) {
        RTE_LOG(ERR, VROUTER,
            "Failed to get statistics for flow id %u - %s\n",
            flow->id,
            error.message ? error.message : "no error message");
        return ret;
    }

    int stats_bytes_bits_nb = sizeof(fe->fe_stats.flow_bytes) * 8;
    int stats_packets_bits_nb = sizeof(fe->fe_stats.flow_packets) * 8;

    uint64_t delta_dev_stats_bytes = query.bytes - flow->stats.bytes;
    uint64_t delta_dev_stats_packets = query.hits - flow->stats.packets;

    uint64_t new_flow_bytes = delta_dev_stats_bytes + fe->fe_stats.flow_bytes;
    uint64_t new_flow_packets = delta_dev_stats_packets + fe->fe_stats.flow_packets;

    fe->fe_stats.flow_bytes = new_flow_bytes;
    fe->fe_stats.flow_bytes_oflow += new_flow_bytes >> stats_bytes_bits_nb;
    fe->fe_stats.flow_packets = new_flow_packets;
    fe->fe_stats.flow_packets_oflow += new_flow_packets >> stats_packets_bits_nb;

    flow->stats.bytes = query.bytes;
    flow->stats.packets = query.hits;

    return 0;
}

static int
vr_dpdk_n3k_offload_flow_iter(struct vr_n3k_offload_flow **flow, uint32_t *next)
{
    if (!flows)
        return -EINVAL;

    while (*next < flows_count && flows[*next] == NULL)
        (*next)++;

    if (*next >= flows_count)
        return -ENOENT;

    flow = &flows[*next];
    return 0;
}

int
vr_dpdk_n3k_offload_flow_update_with_offload_entry(
    struct vr_n3k_offload_flow *flow,
    struct vr_n3k_offload_entry *offload_entry)
{
    struct vr_n3k_rte_flow_package flow_package =
        vr_dpdk_n3k_offload_entry_to_rte_flow(offload_entry);
    if (flow_package.error) {
        RTE_LOG(ERR, VROUTER,
                "%s(): vr_dpdk_n3k_offload_entry_to_rte_flow "
                "failed: %d\n",
                __func__, flow_package.error);
        return -1;
    }

    /* Remove current hw flow */
    if (flow->handle != NULL) {
        vr_dpdk_n3k_offload_destroy_hw_flow(
            flow->handle, flow->hw_port_id, flow->id);
        flow->handle = NULL;
    }

    /* Offload updated flow */
    struct rte_flow_error error;
    static struct rte_flow_attr attr = {
        .ingress = 1,
    };

    flow->hw_port_id = offload_entry->src_vif->port_id;

    flow->handle = rte_flow_create(flow->hw_port_id, &attr,
                                    flow_package.pattern,
                                    flow_package.actions, &error);

    if (flow->handle == NULL) {
        RTE_LOG(ERR, VROUTER,
                "%s(): Failed to create flow %d: [%d]: %s\n",
                __func__, flow->id, error.type,
                error.message ? error.message
                                : "No error message");
        return -1;
    }

    return 0;
}

int
vr_dpdk_n3k_offload_flow_update(
    struct vr_n3k_offload_flow *flow)
{
    struct vr_n3k_offload_entry offload_entry;
    if (vr_dpdk_n3k_fill_offload_entry(flow, &offload_entry) != 0)
        return -1;

    return vr_dpdk_n3k_offload_flow_update_with_offload_entry(
        flow, &offload_entry);
}

void
vr_dpdk_n3k_offload_flow_vif_update(struct vr_n3k_offload_interface *vif)
{
    struct vr_n3k_offload_flow *flow = NULL;
    uint32_t i = 0;

    while (vr_dpdk_n3k_offload_flow_iter(&flow, &i) >= 0) {
        struct vr_n3k_offload_entry offload_entry;

        if (vr_dpdk_n3k_fill_offload_entry_partial_start(flow, &offload_entry) != 0)
            continue;

        if (offload_entry.src_vif != vif &&
            offload_entry.dst_vif != vif)
            continue;

        if (vr_dpdk_n3k_fill_offload_entry_partial_end(flow, &offload_entry) != 0)
            continue;

        if(vr_dpdk_n3k_offload_flow_update_with_offload_entry(flow, &offload_entry) != 0) {
            RTE_LOG(ERR, VROUTER,
                "%s(): Failed to update flow %d\n",
                __func__, flow->id);
        }
    }
}
