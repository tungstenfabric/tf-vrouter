/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_offloads.h"

#include <stdio.h>
#include <stdbool.h>

#include <arpa/inet.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_log.h>

#include <vr_dpdk.h>
#include <vr_flow.h>
#include <vr_offloads.h>

#include "vr_dpdk_n3k_interface.h"
#include "vr_dpdk_n3k_missing_mirror.h"
#include "vr_dpdk_n3k_mpls.h"
#include "vr_dpdk_n3k_flow.h"
#include "vr_dpdk_n3k_vxlan.h"
#include "vr_dpdk_n3k_packet_metadata.h"
#include "vr_dpdk_n3k_packet_parser.h"
#include "vr_dpdk_n3k_config.h"
#include "vr_dpdk_n3k_offload_hold.h"

extern unsigned int vr_bridge_entries;
extern unsigned int datapath_offloads;

rte_spinlock_t vr_dpdk_n3k_offload_spinlock __rte_cache_aligned;

static void
debug_print_packet_key_and_metadata(
        const struct vr_packet *pkt,
        const struct vr_dpdk_n3k_packet_key *key,
        const struct vr_dpdk_n3k_packet_metadata *metadata)
{
    char ip_addr[40];

    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: printing parsed packet\n", __func__);
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: pkt=%p\n", __func__, pkt);

    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key\n", __func__);
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->nh_id    = %u\n", __func__,
        key->nh_id);

    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->src_ip   = %s\n", __func__,
        vr_dpdk_n3k_convert_ip_to_str(ip_addr, &key->ip.src, key->ip.type));
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->dst_ip   = %s\n", __func__,
        vr_dpdk_n3k_convert_ip_to_str(ip_addr, &key->ip.dst, key->ip.type));

    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->proto    = %u\n", __func__,
        key->proto);
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->src_port = %u\n", __func__,
        rte_be_to_cpu_16(key->src_port));
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: key->dst_port = %u\n", __func__,
        rte_be_to_cpu_16(key->dst_port));

    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s: metadata\n", __func__);

    RTE_LOG(DEBUG, OFFLOAD_PACKET,
        "%s: metadata->eth_hdr      = %u\n", __func__,
        metadata->eth_hdr_present);

    if (metadata->eth_hdr_present) {
        RTE_LOG(DEBUG, OFFLOAD_PACKET,
            "%s: metadata->inner_src_mac  = " MAC_FORMAT "\n", __func__,
            MAC_VALUE(&metadata->inner_src_mac[0]));
        RTE_LOG(DEBUG, OFFLOAD_PACKET,
            "%s: metadata->inner_dst_mac  = " MAC_FORMAT "\n", __func__,
            MAC_VALUE(&metadata->inner_dst_mac[0]));
    }
}

static int
vr_dpdk_n3k_offload_packet_parse(struct vr_packet *pkt)
{
    RTE_LOG(DEBUG, OFFLOAD_PACKET, "%s() called; pkt=%p\n", __func__, pkt);

    struct vr_dpdk_n3k_packet_key key;
    struct vr_dpdk_n3k_packet_metadata metadata;
    int ret;

    ret = vr_dpdk_n3k_parse_packet(pkt, &key, &metadata);
    if (ret != 0) {
        RTE_LOG(DEBUG, OFFLOAD_PACKET,
            "%s(): vr_dpdk_n3k_parse_packet() returned %d for pkt=%p\n",
            __func__, ret, pkt);
        return ret;
    } else
        debug_print_packet_key_and_metadata(pkt, &key, &metadata);

    ret = vr_dpdk_n3k_packet_metadata_insert_copy(&key, &metadata, false);
    if (ret != 0) {
        RTE_LOG(DEBUG, OFFLOAD_PACKET,
            "%s(): vr_dpdk_n3k_packet_metadata_insert_copy() returned %d for pkt=%p\n",
            __func__, ret, pkt);
    }
    return ret;
}

/* When vrouter calls this function, all the packet processing had stopped (by
 * shutting interfaces) and all the structures have been re-initialized.
 * Because of that, we don't need to consider interaction of this callback with
 * other threads, except of interaction with service cores (which are
 * unaffected by the reset) -- we need to provide thread safety wrt to
 * aging_service_core and remove_unused_metadata_service_core.
 */
static int
vr_dpdk_n3k_offload_soft_reset(void)
{
    struct vrouter *router = vrouter_get(0);
    int ret;

    vr_dpdk_n3k_offload_interface_exit();
    ret = vr_dpdk_n3k_offload_interface_init(router->vr_max_interfaces);
    if (ret)
        return ret;

    vr_dpdk_n3k_offload_vxlan_exit();
    ret = vr_dpdk_n3k_offload_vxlan_init(router->vr_max_nexthops);
    if (ret)
        return ret;

    vr_dpdk_n3k_offload_mpls_exit();
    ret = vr_dpdk_n3k_offload_mpls_init(router->vr_max_nexthops);
    if (ret)
        return ret;

    vr_dpdk_n3k_offload_missing_mirror_exit_all();
    ret = vr_dpdk_n3k_offload_missing_mirror_init_all();
    if (ret)
        return ret;

    /* We don't need to reset offload_hold, as it's cleared by
     * vr_dpdk_n3k_offload_flow_reset_unlocked */

    vr_dpdk_n3k_packet_metadata_reset();

    vr_dpdk_n3k_offload_lock();
    vr_dpdk_n3k_offload_flow_reset_unlocked();
    vr_dpdk_n3k_offload_unlock();

    return 0;
}

static int
vr_dpdk_n3k_offload_flow_set_threadsafe(
    struct vr_flow_entry *fe, uint32_t fe_index, struct vr_flow_entry *rfe)
{
    int ret = 0;
    vr_dpdk_n3k_offload_lock();
    ret = vr_dpdk_n3k_offload_flow_set_unlocked(fe, fe_index, rfe);
    vr_dpdk_n3k_offload_unlock();
    return ret;
}

static int
vr_dpdk_n3k_offload_flow_del_threadsafe(struct vr_flow_entry *fe)
{
    vr_dpdk_n3k_offload_lock();
    int ret = vr_dpdk_n3k_offload_flow_del_unlocked(fe);
    vr_dpdk_n3k_offload_unlock();
    return ret;
}

static int
vr_dpdk_n3k_offload_flow_stats_update_threadsafe(struct vr_flow_entry *fe)
{
    vr_dpdk_n3k_offload_lock();
    int ret = vr_dpdk_n3k_offload_flow_stats_update_unlocked(fe);
    vr_dpdk_n3k_offload_unlock();
    return ret;
}

static int
vr_dpdk_n3k_offload_mirror_add_threadsafe(
    struct vr_mirror_entry *mirror, unsigned int index)
{
    vr_dpdk_n3k_offload_lock();
    if (mirror->mir_rid == 0) {
        vr_dpdk_n3k_offload_missing_mirror_flows_unlocked(index);
    }
    vr_dpdk_n3k_offload_unlock();
    return 0;
}

static int
vr_dpdk_n3k_offload_nexthop_add_threadsafe(struct vr_nexthop *nh)
{
    vr_dpdk_n3k_offload_lock();
    if (vr_dpdk_n3k_offload_nexthop_validate(nh) == 0) {
        vr_dpdk_n3k_offload_missing_nexthop_flows_unlocked(nh->nh_id);
    }
    vr_dpdk_n3k_offload_unlock();
    return 0;
}

static char n3k_voo_handler_id[] = "N3K offloads";

static const struct vr_offload_ops vr_dpdk_n3k_offload_ops = {
    .voo_handler_id = n3k_voo_handler_id,

    .voo_soft_reset = vr_dpdk_n3k_offload_soft_reset,

    .voo_packet_parse = vr_dpdk_n3k_offload_packet_parse,

    .voo_flow_set = vr_dpdk_n3k_offload_flow_set_threadsafe,
    .voo_flow_del = vr_dpdk_n3k_offload_flow_del_threadsafe,
    .voo_flow_stats_update = vr_dpdk_n3k_offload_flow_stats_update_threadsafe,

    .voo_interface_add = vr_dpdk_n3k_offload_interface_add,
    .voo_interface_del = vr_dpdk_n3k_offload_interface_del,

    .voo_mpls_add = vr_dpdk_n3k_offload_mpls_add,
    .voo_mpls_del = vr_dpdk_n3k_offload_mpls_del,

    .voo_vxlan_add = vr_dpdk_n3k_offload_vxlan_add,
    .voo_vxlan_del = vr_dpdk_n3k_offload_vxlan_del,

    .voo_mirror_add = vr_dpdk_n3k_offload_mirror_add_threadsafe,

    .voo_nexthop_add = vr_dpdk_n3k_offload_nexthop_add_threadsafe,
};

static const struct vr_offload_ops *n3k_offload_ops = NULL;

static void
vr_dpdk_n3k_offload_ops_exit(void)
{
    n3k_offload_ops = NULL;

    vr_dpdk_n3k_offload_lock();

    vr_dpdk_n3k_offload_missing_mirror_exit_all();
    vr_dpdk_n3k_offload_flow_exit();
    vr_dpdk_n3k_offload_mpls_exit();
    vr_dpdk_n3k_offload_vxlan_exit();
    vr_dpdk_n3k_offload_interface_exit();
    vr_dpdk_n3k_packet_metadata_exit();
    vr_dpdk_n3k_offload_hold_exit();
    vr_dpdk_n3k_offload_unlock();
}

static int
vr_dpdk_n3k_offload_ops_init(struct vrouter *router)
{
    int ret = 0;

    vr_compute_size_oflow_table();
    const unsigned int flow_entries = vr_flow_entries + vr_oflow_entries;

    rte_spinlock_init(&vr_dpdk_n3k_offload_spinlock);

    ret = vr_dpdk_n3k_offload_interface_init(router->vr_max_interfaces);
    if (ret)
        goto error;

    ret = vr_dpdk_n3k_offload_vxlan_init(router->vr_max_nexthops);
    if (ret)
        goto error;

    ret = vr_dpdk_n3k_offload_mpls_init(router->vr_max_nexthops);
    if (ret)
        goto error;

    ret = vr_dpdk_n3k_offload_flow_init(flow_entries);
    if (ret)
        goto error;

    ret = vr_dpdk_n3k_offload_missing_mirror_init_all();
    if (ret)
        goto error;

    ret = vr_dpdk_n3k_packet_metadata_init(2 * flow_entries);
    if (ret)
        goto error;

    ret = vr_dpdk_n3k_offload_hold_init(flow_entries);
    if (ret)
        goto error;

    n3k_offload_ops = &vr_dpdk_n3k_offload_ops;

    return 0;

error:
    vr_dpdk_n3k_offload_ops_exit();
    return ret;
}

void
vr_dpdk_n3k_offload_exit(void)
{
    bool offload_enabled = vr_dpdk_n3k_config_is_n3k_enabled() &&
        datapath_offloads;

    if (!offload_enabled) {
        return;
    }

    vr_offload_unregister();
    vr_dpdk_n3k_offload_ops_exit();
}

int
vr_dpdk_n3k_offload_init(void)
{
    bool offload_enabled = vr_dpdk_n3k_config_is_n3k_enabled() &&
        datapath_offloads;

    if (!offload_enabled) {
        return 0;
    }

    /* TODO(n3k): Handle multiple vrouters */
    int ret = vr_dpdk_n3k_offload_ops_init(vrouter_get(0));
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "Initialization of N3K vr_offload_ops failed; ret = %s\n",
            rte_strerror(ret));
        return ret;
    }

    vr_offload_unregister();
    ret = vr_offload_register(n3k_offload_ops);
    if (ret != 0) {
        RTE_LOG(ERR, VROUTER, "vr_offload_register() failed; ret = %s\n",
            rte_strerror(ret));

        vr_dpdk_n3k_offload_ops_exit();

        return ret;
    }

    return 0;
}
