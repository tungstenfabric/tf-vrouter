/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a 
 * Delaware corporation, having its principal place of business 
 * at 2200 Mission College Boulevard, 
 * Santa Clara, California 95052, USA
 */

#include <vr_interface.h>
#include "vr_dpdk_representor.h"

static struct vr_dpdk_representor_ops *representor_ops;

void
vr_dpdk_representor_ops_register(struct vr_dpdk_representor_ops *ops)
{
    representor_ops = ops;
}

void
vr_dpdk_representor_ops_deregister(void)
{
    representor_ops = NULL;
}

enum vr_dpdk_representor_op_res
vr_dpdk_representor_add(struct vr_interface *vif)
{
    struct vr_dpdk_representor_ops *ops = representor_ops;

    if (!ops || !ops->vif_add) {
        return VR_DPDK_REPRESENTOR_OP_RES_NOT_HANDLED;
    }

    return ops->vif_add(vif);
}

enum vr_dpdk_representor_op_res
vr_dpdk_representor_del(struct vr_interface *vif)
{
    struct vr_dpdk_representor_ops *ops = representor_ops;

    if (!ops || !ops->vif_del) {
        return VR_DPDK_REPRESENTOR_OP_RES_NOT_HANDLED;
    }

    return ops->vif_del(vif);
}

enum vr_dpdk_representor_op_res
vr_dpdk_representor_stats_update(struct vr_interface *vif)
{
    struct vr_dpdk_representor_ops *ops = representor_ops;

    if (!ops || !ops->stats_update) {
        return VR_DPDK_REPRESENTOR_OP_RES_NOT_HANDLED;
    }

    return ops->stats_update(vif);
}
