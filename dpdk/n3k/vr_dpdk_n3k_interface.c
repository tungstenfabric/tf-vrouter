/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "offload_entry/vr_dpdk_n3k_offload_entry.h"
#include "vr_dpdk_n3k_missing_mirror.h"
#include "vr_dpdk_n3k_interface.h"
#include "vr_dpdk_n3k_flow.h"

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_pmd_n3k.h>

#include "vr_dpdk.h"
#include "vr_interface.h"

static uint16_t interfaces_count;
static struct vr_n3k_offload_interface **interfaces;

int
vr_dpdk_n3k_offload_interface_init(uint16_t count)
{
    interfaces = rte_zmalloc("n3k_offload_vif", count * sizeof(*interfaces), 0);
    if (interfaces == NULL)
        return -ENOMEM;

    interfaces_count = count;

    if (vr_dpdk_n3k_offload_missing_mirror_vifs_init(128) != 0)
        return -1;

    return 0;
}

void
vr_dpdk_n3k_offload_interface_exit(void)
{
    int idx;

    for (idx = 0; idx < interfaces_count; ++idx) {
        rte_free(interfaces[idx]);
        interfaces[idx] = NULL;
    }

    rte_free(interfaces);
    interfaces = NULL;

    vr_dpdk_n3k_offload_missing_mirror_vifs_exit();
}

struct vr_n3k_offload_interface *
vr_dpdk_n3k_offload_interface_get(uint16_t id)
{
    if (id >= interfaces_count)
        return NULL;

    return interfaces[id];
}

static inline int
vif_to_port_id(
    struct vr_interface *vif, uint16_t *port_id)
{
    struct vr_dpdk_ethdev *repr_dev = (struct vr_dpdk_ethdev *)vif->vif_os;

    if (repr_dev == NULL) {
        RTE_LOG(ERR, VROUTER,
            "Failed to translate vr_interface into port_id\n");
        return -EINVAL;
    }

    *port_id = repr_dev->ethdev_port_id;

    return 0;
}

void
vr_dpdk_n3k_offload_interface_insert(struct vr_n3k_offload_interface *vif)
{
    interfaces[vif->id] = vif;
}

int
vr_dpdk_n3k_offload_interface_add(struct vr_interface *vif)
{
    bool update_hw_flows = false;
    int ret;

    RTE_LOG(
        DEBUG, VROUTER,
        "%s() called; vif=%p; id=%d; type=%d; flags=%#x; mirror=%d;\n",
        __func__, vif, vif->vif_idx, vif->vif_type, vif->vif_flags,
        vif->vif_mirror_id
    );

    /* TODO(n3k): Handle multiple routers */
    if (vif->vif_rid != 0)
        return 0;

    /* TODO(n3k): Do we need other interfaces? */
    if (!vif_is_fabric(vif) && !vif_is_virtual(vif))
        return 0;

    uint16_t port_id;
    ret = vif_to_port_id(vif, &port_id);
    if (ret)
        return ret;

    struct vr_n3k_offload_interface *ovif = interfaces[vif->vif_idx];

    /* TODO(n3k): What to do when existing interface has been changed? */

    if (ovif == NULL) {
        ovif = rte_zmalloc("n3k_offload_vif", sizeof(*ovif), 0);
        if (ovif == NULL)
            return -ENOMEM;
    } else if (ovif->mirror_id != vif->vif_mirror_id) {
        update_hw_flows = true;
    }

    ovif->id = vif->vif_idx;
    ovif->type = vif->vif_type;
    ovif->flags = vif->vif_flags;
    ovif->port_id = port_id;
    ovif->mirror_id = vif->vif_mirror_id;
    rte_memcpy(ovif->mac, vif->vif_mac, VR_ETHER_ALEN);

    vr_dpdk_n3k_offload_interface_insert(ovif);

    if (update_hw_flows) {
        vr_dpdk_n3k_offload_flow_vif_update(ovif);
    }

    vr_dpdk_n3k_offload_missing_vif_flows(vif->vif_idx);

    return 0;
}

int
vr_dpdk_n3k_offload_interface_del(struct vr_interface *vif)
{
    RTE_LOG(
        DEBUG, VROUTER,
        "%s() called; vif=%p; id=%d; type=%d; flags=%#x; mirror=%d;\n",
        __func__, vif, vif->vif_idx, vif->vif_type, vif->vif_flags,
        vif->vif_mirror_id
    );

    /* TODO(n3k): Handle multiple routers */
    if (vif->vif_rid != 0)
        return 0;

    rte_free(interfaces[vif->vif_idx]);
    interfaces[vif->vif_idx] = NULL;

    return 0;
}
