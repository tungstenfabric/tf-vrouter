/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <getopt.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_launch.h>
#include <rte_log.h>

#include "vr_dpdk.h"
#include "../vr_dpdk_pmd_context.h"
#include "vr_dpdk_n3k_config.h"
#include "vr_dpdk_n3k_offloads.h"
#include "vr_dpdk_n3k_service_core.h"
#include "representor/vr_dpdk_n3k_representor.h"

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
    if (vr_argc < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): invalid vrouter's cli arguments count\n", __func__);
        return -EINVAL;
    }

    return vr_dpdk_n3k_config_parse_opt(vr_argc, vr_argv, opt);
}

bool
vr_dpdk_n3k_pmd_ctx_is_enabled(void)
{
    return vr_dpdk_n3k_config_is_n3k_enabled();
}

int
vr_dpdk_n3k_pmd_ctx_init(int eal_argc, char *eal_argv[])
{
    struct vr_dpdk_n3k_config_eal_args updated_args;

    RTE_LOG(INFO, VROUTER, "%s(): start\n", __func__);

    if (eal_argc < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): invalid EAL argc\n", __func__);
        return -EINVAL;
    }

    vr_dpdk_n3k_config_init();

    int ret = vr_dpdk_n3k_config_get_updated_eal_args(
      eal_argc, eal_argv, &updated_args);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): EAL arguments update failed; Error: %d\n", __func__, ret);
        return ret;
    }

    vr_dpdk_n3k_representor_init();

    ret = rte_eal_init(updated_args.argc, updated_args.argv);

    free(updated_args.argv);

    if (ret == -1) {
        RTE_LOG(ERR, VROUTER,
            "%s(): EAL init failed; Error: %d\n", __func__, -rte_errno);
        return -rte_errno;
    }

    ret = vr_dpdk_n3k_service_core_init();
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): service core init failed; Error: %d\n", __func__, ret);
        return ret;
    }

    RTE_LOG(INFO, VROUTER, "%s(): succeeded\n", __func__);

    return 0;
}

int
vr_dpdk_n3k_pmd_ctx_exit(void)
{
    RTE_LOG(INFO, VROUTER, "%s(): start\n", __func__);

    int ret = vr_dpdk_n3k_service_core_exit();
    if (ret) {
        return ret;
    }

    vr_dpdk_n3k_representor_exit();
    vr_dpdk_n3k_config_exit();

    ret = rte_eal_cleanup();
    if (ret) {
        return ret;
    }

    RTE_LOG(INFO, VROUTER, "%s(): succeeded\n", __func__);

    return 0;
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
    RTE_LOG(INFO, VROUTER, "%s(): start\n", __func__);

    rte_log_set_global_level(RTE_LOG_DEBUG);

    int ret = vr_dpdk_n3k_service_core_launch();
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): service core launch failed; Error: %d\n", __func__, ret);
        return ret;
    }

    ret = vr_dpdk_n3k_offload_init();
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): N3K offload init failed; Error: %d\n", __func__, ret);
        goto service_stop;
    }

    RTE_LOG(INFO, VROUTER, "%s(): launching lcores\n", __func__);

    ret = rte_eal_mp_remote_launch(launch_cb, NULL, CALL_MASTER);

    RTE_LOG(INFO, VROUTER,
         "%s(): master lcore's work done: starting deinit; Retcode: %d\n",
         __func__, ret);

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
    .is_enabled = vr_dpdk_n3k_pmd_ctx_is_enabled,
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
