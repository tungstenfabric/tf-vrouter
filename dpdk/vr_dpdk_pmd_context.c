/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <errno.h>

#include <rte_eal.h>
#include <rte_launch.h>

#include "vr_dpdk_pmd_context.h"

static struct vr_dpdk_pmd_ctx *pmd_ctx;

void
vr_dpdk_pmd_ctx_register(struct vr_dpdk_pmd_ctx *ctx)
{
    pmd_ctx = ctx;
}

void
vr_dpdk_pmd_ctx_deregister(void)
{
    pmd_ctx = NULL;
}

int
vr_dpdk_pmd_ctx_print_usage(void)
{
    struct vr_dpdk_pmd_ctx *ctx = pmd_ctx;

    if (ctx != NULL && ctx->print_usage != NULL) {
        return ctx->print_usage();
    }

    return -ENOTSUP;
}

int
vr_dpdk_pmd_ctx_parse_opt(int vr_argc, char *vr_argv[], size_t optindex, char opt, char *optarg)
{
    struct vr_dpdk_pmd_ctx *ctx = pmd_ctx;

    if (ctx != NULL && ctx->parse_opt != NULL) {
        return ctx->parse_opt(vr_argc, vr_argv, optindex, opt, optarg);
    }

    return -ENOTSUP;
}

int
vr_dpdk_pmd_ctx_init(int eal_argc, char *eal_argv[])
{
    struct vr_dpdk_pmd_ctx *ctx = pmd_ctx;
    bool init_callable = ctx != NULL &&
                         ctx->is_enabled != NULL &&
                         ctx->is_enabled() &&
                         ctx->init != NULL;

    if (init_callable) {
        return ctx->init(eal_argc, eal_argv);
    }

    return rte_eal_init(eal_argc, eal_argv);
}

int
vr_dpdk_pmd_ctx_exit(void)
{
    struct vr_dpdk_pmd_ctx *ctx = pmd_ctx;
    bool exit_callable = ctx != NULL &&
                         ctx->is_enabled != NULL &&
                         ctx->is_enabled() &&
                         ctx->exit != NULL;

    if (exit_callable) {
        return ctx->exit();
    }

    return rte_eal_cleanup();
}

int
vr_dpdk_pmd_ctx_lcore_request(char *lcores_string, size_t lcores_string_sz, char *service_core_mapping)
{
    struct vr_dpdk_pmd_ctx *ctx = pmd_ctx;
    bool request_callable = ctx != NULL &&
                            ctx->is_enabled != NULL &&
                            ctx->is_enabled() &&
                            ctx->lcore_request != NULL;

    if (request_callable) {
        return ctx->lcore_request(lcores_string, lcores_string_sz, service_core_mapping);
    }

    return -ENOTSUP;
}

int
vr_dpdk_pmd_ctx_launch_lcores(vr_dpdk_lcore_launch_cb_t launch_cb)
{
    struct vr_dpdk_pmd_ctx *ctx = pmd_ctx;
    bool launch_callable = ctx != NULL &&
                           ctx->is_enabled != NULL &&
                           ctx->is_enabled() &&
                           ctx->launch_lcores != NULL;

    if (launch_callable) {
        return ctx->launch_lcores(launch_cb);
    }

    return rte_eal_mp_remote_launch(launch_cb, NULL, CALL_MASTER);
}
