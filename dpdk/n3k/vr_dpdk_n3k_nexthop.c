/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_nexthop.h"
#include "offload_entry/vr_dpdk_n3k_offload_entry.h"
#include "vr_dpdk_n3k_missing_mirror.h"
#include "vr_dpdk_n3k_flow.h"

#include <rte_log.h>
#include <rte_malloc.h>

#include "vr_dpdk.h"
#include "vr_nexthop.h"
#include "vr_packet.h"

static uint32_t nexthops_count;
static struct vr_n3k_offload_nexthop **nexthops;

int
vr_dpdk_n3k_offload_nexthop_init(uint32_t count)
{
    nexthops = rte_zmalloc("n3k_offload_nh", count * sizeof(*nexthops), 0);
    if (nexthops == NULL)
        return -ENOMEM;

    nexthops_count = count;

    if (vr_dpdk_n3k_offload_missing_mirror_nexthops_init(128) != 0)
        return -1;

    return 0;
}

void
vr_dpdk_n3k_offload_nexthop_exit(void)
{
    int idx;

    for (idx = 0; idx < nexthops_count; ++idx) {

        if (nexthops[idx] != NULL && nexthops[idx]->type == NH_COMPOSITE &&
                nexthops[idx]->cnh_cnt > 0) {
            rte_free(nexthops[idx]->component_nhs);
            nexthops[idx]->component_nhs = NULL;
        }

        rte_free(nexthops[idx]);
        nexthops[idx] = NULL;
    }

    rte_free(nexthops);
    nexthops = NULL;

    vr_dpdk_n3k_offload_missing_mirror_nexthops_exit();
}

struct vr_n3k_offload_nexthop *
vr_dpdk_n3k_offload_nexthop_get(uint32_t id)
{
    if (id >= nexthops_count)
        return NULL;

    return nexthops[id];
}

void
vr_dpdk_n3k_offload_nexthop_insert(struct vr_n3k_offload_nexthop *nh)
{
    nexthops[nh->id] = nh;
}

int
vr_dpdk_n3k_offload_nexthop_add(struct vr_nexthop *nh)
{
    /* TODO(n3k): Handle multiple routers */
    if (nh->nh_rid != 0)
        return 0;

    struct vr_n3k_offload_nexthop *onh = nexthops[nh->nh_id];

    /* TODO(n3k): What to do when existing nexthop has been changed? */

    if (onh == NULL) {
        onh = rte_zmalloc("n3k_offload_nh", sizeof(*onh), 0);
        if (onh == NULL)
            return -ENOMEM;
    }

    onh->id = nh->nh_id;
    onh->type = nh->nh_type;
    onh->nh_family = nh->nh_family;
    onh->nh_flags = nh->nh_flags;
    onh->interface_id = nh->nh_dev != NULL ? nh->nh_dev->vif_idx : -1;
    onh->vrf = nh->nh_vrf;

    memset(onh->src_mac, 0, VR_ETHER_ALEN);
    memset(onh->dst_mac, 0, VR_ETHER_ALEN);

    onh->tunnel_src_ip = 0;
    onh->tunnel_dst_ip = 0;

    if (nh->nh_data_size >= 2 * VR_ETHER_ALEN) {
        struct vr_eth *eth = (struct vr_eth *)nh->nh_data;
        rte_memcpy(onh->src_mac, eth->eth_smac, VR_ETHER_ALEN);
        rte_memcpy(onh->dst_mac, eth->eth_dmac, VR_ETHER_ALEN);
    }

    if (onh->type == NH_TUNNEL) {
        onh->tunnel_src_ip = nh->nh_vxlan_tun_sip;
        onh->tunnel_dst_ip = nh->nh_vxlan_tun_dip;
    }

    if (onh->type == NH_COMPOSITE) {
        if (nh->nh_component_nh != NULL) {
            onh->cnh_cnt = nh->nh_component_cnt;

            onh->component_nhs = rte_zmalloc("n3k_offload_nh_cmp",
                onh->cnh_cnt * sizeof(struct vr_n3k_offload_nh_label), 0);
            if (onh->component_nhs == NULL)
                return -ENOMEM;

            uint16_t i;
            for (i = 0; i < onh->cnh_cnt; ++i) {
                if (nh->nh_component_nh[i].cnh != NULL) {
                    onh->component_nhs[i].label = nh->nh_component_nh[i].cnh_label;
                    onh->component_nhs[i].nh_idx = nh->nh_component_nh[i].cnh->nh_id;
                } else {
                    RTE_LOG(
                        DEBUG, VROUTER,
                        "Composite nh=%p; id=%d; type=%d; does not have "
                        "pointer to component nexthop and should have %d; \n",
                        nh, nh->nh_id, nh->nh_type, nh->nh_component_cnt
                    );
                }
            }
        } else {
            RTE_LOG(
                DEBUG, VROUTER,
                "Composite nh=%p; id=%d; type=%d; does not have "
                "component nexthops table and should have %d; \n",
                nh, nh->nh_id, nh->nh_type, nh->nh_component_cnt
            );
        }
    }

    RTE_LOG(
        DEBUG, VROUTER,
        "%s() called; nh=%p; id=%d; type=%d; vif=%d; vrf=%d; family=%d; "
        "smac=" MAC_FORMAT "; dmac=" MAC_FORMAT ";\n",
        __func__, nh, nh->nh_id, nh->nh_type,
        nh->nh_dev != NULL ? nh->nh_dev->vif_idx : -1,
        nh->nh_vrf, nh->nh_family,
        MAC_VALUE(onh->src_mac), MAC_VALUE(onh->dst_mac)
    );

    vr_dpdk_n3k_offload_nexthop_insert(onh);

    vr_dpdk_n3k_offload_missing_nexthop_flows(nh->nh_id);

    return 0;
}

int
vr_dpdk_n3k_offload_nexthop_del(struct vr_nexthop *nh)
{
    RTE_LOG(
        DEBUG, VROUTER,
        "%s() called; nh=%p; id=%d; type=%d; vif=%d; vrf=%d; family=%d;\n",
        __func__, nh, nh->nh_id, nh->nh_type,
        nh->nh_dev != NULL ? nh->nh_dev->vif_idx : -1,
        nh->nh_vrf, nh->nh_family
    );

    /* TODO(n3k): Handle multiple routers */
    if (nh->nh_rid != 0)
        return 0;

    if (nexthops[nh->nh_id] != NULL &&
            nexthops[nh->nh_id]->type == NH_COMPOSITE &&
            nexthops[nh->nh_id]->cnh_cnt > 0) {
        rte_free(nexthops[nh->nh_id]->component_nhs);
        nexthops[nh->nh_id]->component_nhs = NULL;
    }

    rte_free(nexthops[nh->nh_id]);
    nexthops[nh->nh_id] = NULL;

    return 0;
}

int vr_dpdk_n3k_offload_nexthop_get_cnh_idx(
    const struct vr_n3k_offload_nexthop *nh, uint16_t idx, uint32_t *nh_idx)
{
    if (!nh || nh->type != NH_COMPOSITE || idx >= nh->cnh_cnt)
        return -EINVAL;
    *nh_idx = nh->component_nhs[idx].nh_idx;
    return 0;
}

int vr_dpdk_n3k_offload_nexthop_get_cnh_label(
    const struct vr_n3k_offload_nexthop *nh, uint16_t idx, uint32_t *label)
{
    if (!nh || nh->type != NH_COMPOSITE || idx >= nh->cnh_cnt)
        return -EINVAL;
    *label = nh->component_nhs[idx].label;
    return 0;
}
