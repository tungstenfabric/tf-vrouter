/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_vxlan.h"

#include <rte_log.h>
#include <rte_malloc.h>

#include "vr_dpdk.h"

enum { N3K_OFFLOAD_VNI_COUNT = 1 << 24 };

static uint32_t nexthops_count;
static struct vr_n3k_offload_vxlan **vni_to_nh;
static struct vr_n3k_offload_vxlan **nh_to_vni;

int
vr_dpdk_n3k_offload_vxlan_init(uint32_t nh_count)
{
    /* TODO(n3k): This is 128 MB. Use hashtable or indextable */
    vni_to_nh = rte_zmalloc("n3k_offload_vxlan",
        N3K_OFFLOAD_VNI_COUNT * sizeof(*vni_to_nh), 0);
    if (vni_to_nh == NULL)
        return -ENOMEM;

    nh_to_vni = rte_zmalloc("n3k_offload_vxlan",
        nh_count * sizeof(*nh_to_vni), 0);
    if (nh_to_vni == NULL) {
        rte_free(vni_to_nh);
        return -ENOMEM;
    }

    nexthops_count = nh_count;
    return 0;
}

void
vr_dpdk_n3k_offload_vxlan_exit(void)
{
    int idx;

    for (idx = 0; idx < N3K_OFFLOAD_VNI_COUNT; ++idx) {
        rte_free(vni_to_nh[idx]);
        vni_to_nh[idx] = NULL;
    }

    rte_free(nh_to_vni);
    nh_to_vni = NULL;

    rte_free(vni_to_nh);
    vni_to_nh = NULL;
}

struct vr_n3k_offload_vxlan *
vr_dpdk_n3k_offload_vxlan_get_by_vni(uint32_t vnid)
{
    if (vnid >= N3K_OFFLOAD_VNI_COUNT)
        return NULL;

    return vni_to_nh[vnid];
}

struct vr_n3k_offload_vxlan *
vr_dpdk_n3k_offload_vxlan_get_by_nh(uint32_t nh_id)
{
    if (nh_id >= nexthops_count)
        return NULL;

    return nh_to_vni[nh_id];
}

void
vr_dpdk_n3k_offload_vxlan_insert(struct vr_n3k_offload_vxlan *vxlan)
{
    vni_to_nh[vxlan->vnid] = vxlan;
    nh_to_vni[vxlan->nexthop_id] = vxlan;
}

int
vr_dpdk_n3k_offload_vxlan_add(struct vr_nexthop *nh, int vnid)
{
    RTE_LOG(
        DEBUG, VROUTER,
        "%s() called; nh=%p; nh_id=%d; nh_type=%d; vnid=%d;\n",
        __func__, nh, nh->nh_id, nh->nh_type, vnid
    );

    /* TODO(n3k): Handle multiple routers */
    if (nh->nh_rid != 0)
        return 0;

    struct vr_n3k_offload_vxlan *ovxlan = vni_to_nh[vnid];

    /* TODO(n3k): What to do when existing vxlan entry has been changed? */

    if (ovxlan == NULL) {
        ovxlan = rte_zmalloc("n3k_offload_vxlan", sizeof(*ovxlan), 0);
        if (ovxlan == NULL)
            return -ENOMEM;
    } else
        nh_to_vni[ovxlan->nexthop_id] = NULL;

    ovxlan->vnid = vnid;
    ovxlan->nexthop_id = nh->nh_id;

    vr_dpdk_n3k_offload_vxlan_insert(ovxlan);

    return 0;
}

int
vr_dpdk_n3k_offload_vxlan_del(int vnid)
{
    RTE_LOG(DEBUG, VROUTER, "%s() called; vnid=%d;\n", __func__, vnid);

    struct vr_n3k_offload_vxlan *ovxlan = vni_to_nh[vnid];
    vni_to_nh[ovxlan->vnid] = NULL;
    nh_to_vni[ovxlan->nexthop_id] = NULL;
    rte_free(ovxlan);

    return 0;
}
