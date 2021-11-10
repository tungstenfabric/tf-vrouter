/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_PMD_CONTEXT_H__
#define __VR_DPDK_PMD_CONTEXT_H__

#include <stddef.h>

typedef int (*vr_dpdk_lcore_launch_cb_t)(void *);
/*
    An interface for PMDs that require additional configuration and resources from DPDK to work.
    Only used from master lcore
*/

struct vr_dpdk_pmd_ctx {
    int (*parse_opt)(int, char *[], size_t, char, char *);
    //PMD context is responsible for calling rte_eal_init()
    int (*init)(int, char *[]);
    int (*exit)(void);
    int (*lcore_request)(char *, size_t, char *);
    int (*launch_lcores)(vr_dpdk_lcore_launch_cb_t);
    int (*print_usage)(void);
};

void vr_dpdk_pmd_ctx_register(struct vr_dpdk_pmd_ctx *ctx);
void vr_dpdk_pmd_ctx_deregister(void);

int vr_dpdk_pmd_ctx_print_usage(void);
int vr_dpdk_pmd_ctx_parse_opt(int vr_argc, char *vr_argv[], size_t optindex, char opt, char *optarg);
int vr_dpdk_pmd_ctx_init(int eal_argc, char *eal_argv[]);
int vr_dpdk_pmd_ctx_exit(void);
int vr_dpdk_pmd_ctx_lcore_request(char *lcores_string, size_t lcores_string_sz, char *service_lcore_mapping);
int vr_dpdk_pmd_ctx_launch_lcores(vr_dpdk_lcore_launch_cb_t launch_cb);

#endif /*__VR_DPDK_PMD_CONTEXT_H__ */
