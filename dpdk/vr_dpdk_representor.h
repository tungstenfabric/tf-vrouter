/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_REPRESENTOR_H__
#define __VR_DPDK_REPRESENTOR_H__

struct vr_interface;

enum vr_dpdk_representor_op_res {
    VR_DPDK_REPRESENTOR_OP_RES_NOT_HANDLED,
    VR_DPDK_REPRESENTOR_OP_RES_HANDLED_OK,
    VR_DPDK_REPRESENTOR_OP_RES_HANDLED_ERR,
};

typedef enum vr_dpdk_representor_op_res (*vr_dpdk_representor_op_t)(struct vr_interface *);

struct vr_dpdk_representor_ops {
    vr_dpdk_representor_op_t vif_add;
    vr_dpdk_representor_op_t vif_del;
    vr_dpdk_representor_op_t stats_update;
};

void vr_dpdk_representor_ops_register(struct vr_dpdk_representor_ops *);
void vr_dpdk_representor_ops_deregister(void);

enum vr_dpdk_representor_op_res
vr_dpdk_representor_add(struct vr_interface *);

enum vr_dpdk_representor_op_res
vr_dpdk_representor_del(struct vr_interface *);

enum vr_dpdk_representor_op_res
vr_dpdk_representor_stats_update(struct vr_interface *);

#endif /*__VR_DPDK_REPRESENTOR_H__ */
