/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <assert.h>
#include <getopt.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_launch.h>

#include "../vr_dpdk_pmd_context.h"
#include "vr_dpdk_n3k_config.h"
#include "vr_dpdk_n3k_offloads.h"
#include "vr_dpdk_n3k_service_core.h"
#include "vr_dpdk_n3k_representor.h"

int
vr_dpdk_n3k_pmd_ctx_print_usage(void)
{
    vr_dpdk_n3k_config_print_usage();

    return 0;
}

int
vr_dpdk_n3k_pmd_ctx_parse_opt(int vr_argc,
                              char *vr_argv[],
                              __attribute__((unused)) size_t optindex,
                              char opt,
                              __attribute__((unused)) char *optarg)
{
    assert(vr_argc >= 0);

    return vr_dpdk_n3k_config_parse_opt(vr_argc, vr_argv, opt);
}

int
vr_dpdk_n3k_pmd_ctx_init(int eal_argc, char *eal_argv[])
{
    struct vr_dpdk_n3k_config_eal_args updated_args;

    assert(eal_argc >= 0);
    vr_dpdk_n3k_config_init();

    int ret = vr_dpdk_n3k_config_get_updated_eal_args(
      eal_argc, eal_argv, &updated_args);
    if (ret) {
        return ret;
    }

    vr_dpdk_n3k_representor_init();

    ret = rte_eal_init(updated_args.argc, updated_args.argv);

    free(updated_args.argv);

    if (ret == -1) {
        return -rte_errno;
    }

    return vr_dpdk_n3k_service_core_init();
}

int
vr_dpdk_n3k_pmd_ctx_exit(void)
{
    int ret = vr_dpdk_n3k_service_core_exit();
    if (ret) {
        return ret;
    }

    vr_dpdk_n3k_representor_exit();

    vr_dpdk_n3k_config_exit();

    return rte_eal_cleanup();
}

int
vr_dpdk_n3k_pmd_ctx_lcore_request(char *lcores_string,
                                  size_t lcores_string_sz,
                                  char *service_core_mapping)
{
    return vr_dpdk_n3k_service_core_lcore_request(
      lcores_string, lcores_string_sz, service_core_mapping);
}

int
vr_dpdk_n3k_pmd_ctx_launch_lcores(vr_dpdk_lcore_launch_cb_t launch_cb)
{
    int ret = vr_dpdk_n3k_service_core_launch();
    if (ret) {
        return ret;
    }

    ret = vr_dpdk_n3k_offload_init();
    if (ret) {
        goto service_stop;
    }

    ret = rte_eal_mp_remote_launch(launch_cb, NULL, CALL_MASTER);

    vr_dpdk_n3k_offload_exit();

service_stop:
    vr_dpdk_n3k_service_core_stop();

    return ret;
}

struct vr_dpdk_pmd_ctx n3k_ctx = {
    .print_usage = vr_dpdk_n3k_pmd_ctx_print_usage,
    .parse_opt = vr_dpdk_n3k_pmd_ctx_parse_opt,
    .init = vr_dpdk_n3k_pmd_ctx_init,
    .exit = vr_dpdk_n3k_pmd_ctx_exit,
    .lcore_request = vr_dpdk_n3k_pmd_ctx_lcore_request,
    .launch_lcores = vr_dpdk_n3k_pmd_ctx_launch_lcores,
};

RTE_FINI(vr_dpdk_n3k_pmd_ctx_deregister)
{
    vr_dpdk_pmd_ctx_deregister();
}

RTE_INIT(vr_dpdk_n3k_pmd_ctx_register)
{
    // This variable is used by getopt as a switch for printing error message
    // if some option was not recognized.
    // We set it to 0, so the getopt does not print error message, because
    // there could be options meant for us.
    // Also we must set it, before calling parse_opt, so it must be set here
    // or pmd ctx needs to be extended.
    opterr = 0;

    vr_dpdk_pmd_ctx_register(&n3k_ctx);
}
