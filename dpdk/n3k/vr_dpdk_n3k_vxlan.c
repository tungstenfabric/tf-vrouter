/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_vxlan.h"

#include <string.h>

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_atomic.h>

#include "vr_dpdk.h"

enum { N3K_OFFLOAD_VNI_COUNT = 1 << 24 };

static rte_atomic32_t *vni_to_nh;

#define EMPTY_NH UINT32_MAX

int
vr_dpdk_n3k_offload_vxlan_init(uint32_t nh_count)
{
    vni_to_nh = rte_malloc("n3k_offload_vxlan",
        N3K_OFFLOAD_VNI_COUNT * sizeof(*vni_to_nh), 0);

    if (vni_to_nh == NULL)
        return -ENOMEM;

    /* fill with EMPTY_NH */
    memset(vni_to_nh, 0xff, N3K_OFFLOAD_VNI_COUNT * sizeof(*vni_to_nh));

    return 0;
}

void
vr_dpdk_n3k_offload_vxlan_exit(void)
{
    rte_free(vni_to_nh);
    vni_to_nh = NULL;
}

int
vr_dpdk_n3k_offload_vxlan_get_by_vni(uint32_t vnid, struct vr_n3k_offload_vxlan *out)
{
    if (vnid >= N3K_OFFLOAD_VNI_COUNT)
        return -EINVAL;

    uint32_t nh = rte_atomic32_read(&vni_to_nh[vnid]);
    if (nh == EMPTY_NH)
        return -ENOENT;

    out->vnid = vnid;
    out->nexthop_id = nh;
    return 0;
}

int
vr_dpdk_n3k_offload_vxlan_insert_copy_for_test(struct vr_n3k_offload_vxlan vxlan)
{
    if (rte_atomic32_cmpset(
        (volatile uint32_t *)&vni_to_nh[vxlan.vnid].cnt,
        EMPTY_NH,
        vxlan.nexthop_id
    ) == 0)
        return -EEXIST;

    return 0;
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

    rte_atomic32_set(&vni_to_nh[vnid], nh->nh_id);

    return 0;
}

int
vr_dpdk_n3k_offload_vxlan_del(int vnid)
{
    RTE_LOG(DEBUG, VROUTER, "%s() called; vnid=%d;\n", __func__, vnid);

    rte_atomic32_set(&vni_to_nh[vnid], EMPTY_NH);

    return 0;
}
