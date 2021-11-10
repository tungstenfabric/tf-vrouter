/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_REPRESENTOR_MAP_H__
#define __VR_DPDK_N3K_REPRESENTOR_MAP_H__

const char *vr_dpdk_n3k_representor_map_add(struct vr_interface *vif);
void vr_dpdk_n3k_representor_map_delete(struct vr_interface *vif);

int vr_dpdk_n3k_representor_map_init(void);
void vr_dpdk_n3k_representor_map_exit(void);

#endif /* __VR_DPDK_N3K_REPRESENTOR_MAP_H__ */
