/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_N3K_VHOST_H__
#define __VR_N3K_VHOST_H__

#include "../vr_dpdk_virtio.h"
#include "vr_dpdk.h"

#define VR_UVH_VIF_PFX "uvh_vif_"

enum {VIRTIO_RXQ, VIRTIO_TXQ, VIRTIO_QNUM};

int vr_n3k_vhost_vif_add_handler(unsigned char *vif_name, uint32_t vif_idx,
				 uint32_t vif_gen, uint32_t vif_nrxqs,
				 uint32_t vif_ntxqs, uint32_t vif_vdpa_did);
void
vr_n3k_vhost_vif_remove_handler(unsigned char *vif_name);
#endif /* __VR_N3K_VHOST_H__ */
