/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_SERVICE_CORE_H__
#define __VR_DPDK_N3K_SERVICE_CORE_H__

#include <stddef.h>

int vr_dpdk_n3k_service_core_init(void);
int vr_dpdk_n3k_service_core_exit(void);
int vr_dpdk_n3k_service_core_lcore_request(char *, size_t, char *);
int vr_dpdk_n3k_service_core_launch(void);
int vr_dpdk_n3k_service_core_stop(void);

#endif //__VR_DPDK_N3K_SERVICE_CORE_H__
