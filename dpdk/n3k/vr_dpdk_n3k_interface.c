/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_offloads.h"
#include "vr_dpdk_n3k_missing_mirror.h"
#include "vr_dpdk_n3k_interface.h"
#include "vr_dpdk_n3k_flow.h"

#include <rte_log.h>
#include <rte_malloc.h>

#include "vr_dpdk.h"
#include "vr_interface.h"

struct interface_meta {
    bool exists;
    uint8_t mirror_id;
};

/* Note: This array does not need to be protected by any lock, as it's accessed
 * only from add/del callbacks, which vrouter calls only from only one thread
 * (dpdk_lcore_netlink_loop) */
static struct interface_meta *interfaces;

int
vr_dpdk_n3k_offload_interface_init(uint16_t count)
{
    interfaces = rte_zmalloc("n3k_offload_vif", count * sizeof(*interfaces), 0);
    if (interfaces == NULL)
        return -ENOMEM;

    return 0;
}

void
vr_dpdk_n3k_offload_interface_exit(void)
{
    rte_free(interfaces);
    interfaces = NULL;
}

static bool is_vif_supported(const struct vr_interface *vif) {
    /* TODO(n3k): Handle multiple routers */
    if (vif->vif_rid != 0)
        return false;

    if (!vif_is_fabric(vif) && !vif_is_virtual(vif))
        return false;

    if (vif->vif_os == NULL) {
        RTE_LOG(ERR, VROUTER,
            "Failed to translate vr_interface (idx=%hu) into port_id, vif_os is NULL.\n",
            vif->vif_idx);
        return false;
    }
    return true;
}

const struct vr_interface *
vr_dpdk_n3k_offload_interface_get(uint16_t id)
{
    /* Note: Using `__vrouter_get_interface` instead of
     * `vrouter_get_interface`, as we don't need nor want to touch the
     * refcount. See the comment on `vr_dpdk_n3k_offload_nexthop_get */
    const struct vr_interface *vif = __vrouter_get_interface(vrouter_get(0), id);

    if ((vif == NULL) || (!is_vif_supported(vif))) {
        return NULL;
    }

    return vif;
}

int
vr_dpdk_n3k_offload_interface_add(struct vr_interface *vif)
{
    int ret = 0;
    unsigned short id = vif->vif_idx;

    bool mirror_changed = interfaces[id].exists && interfaces[id].mirror_id != vif->vif_mirror_id;

    interfaces[id] = (struct interface_meta) {
        .exists = true,
        .mirror_id = vif->vif_mirror_id,
    };

    if (!is_vif_supported(vif)) {
        return 0;
    }

    vr_dpdk_n3k_offload_lock();

    if (mirror_changed) {
        ret = vr_dpdk_n3k_offload_flow_vif_update_unlocked(vif);
        if (ret) {
            RTE_LOG(ERR, VROUTER, "%s(): vif's flows update failed: %d\n",
                __func__, ret);
            goto out;
        }
    }

    vr_dpdk_n3k_offload_missing_vif_flows_unlocked(vif->vif_idx);

out:
    vr_dpdk_n3k_offload_unlock();

    return ret;
}

int
vr_dpdk_n3k_offload_interface_del(struct vr_interface *vif)
{
    interfaces[vif->vif_idx].exists = false;
    return 0;
}
