/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <sys/queue.h>

#include <rte_eal.h>
#include <rte_dev.h>
#include <string.h>

#include "vr_dpdk.h"
#include "vr_dpdk_n3k_config.h"
#include "vr_dpdk_n3k_service_core.h"

#define VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER(match, routine)                 \
    {                                                                          \
        .match_str = (match), .handler_routine = (routine)                     \
    }

#define REPRESENTORS_MAX_NUMBER 2

struct vr_dpdk_n3k_eal_opt {
    STAILQ_ENTRY(vr_dpdk_n3k_eal_opt) next;

    char *opt;
    char *value;
};

STAILQ_HEAD(vr_dpdk_n3k_eal_opts, vr_dpdk_n3k_eal_opt);

struct vr_dpdk_n3k_config {
    char phy_representor_name[REPRESENTORS_MAX_NUMBER][RTE_DEV_NAME_MAX_LEN];
    size_t phy_representor_name_nbr;
    bool drop_offload_enabled;
    bool aging_service_core_enabled;
    bool force_vdpa_mapping;
    bool multihoming_enabled;
    struct vr_dpdk_n3k_eal_opts eal_opts;
};

struct vr_dpdk_n3k_config n3k_config = { .phy_representor_name_nbr = 0,
                                         .drop_offload_enabled = true,
                                         .aging_service_core_enabled = false,
                                         .force_vdpa_mapping = false,
                                         .multihoming_enabled = false,
                                         .eal_opts = STAILQ_HEAD_INITIALIZER(
                                           n3k_config.eal_opts) };

typedef int (*option_handler_t)(struct vr_dpdk_n3k_config *, size_t, char **);

struct vr_dpdk_n3k_option_handler {
    const char *match_str;
    option_handler_t handler_routine;
};

static size_t
get_argv_last_filled_pos(size_t argv_sz, char **argv)
{
    size_t last_filled_pos = 0;
    for (; last_filled_pos < argv_sz; ++last_filled_pos) {
        if (argv[last_filled_pos] == NULL) {
            break;
        }
    }

    return --last_filled_pos;
}

static size_t
get_n3k_eal_argc(struct vr_dpdk_n3k_config *cfg, size_t vr_eal_argc)
{
    struct vr_dpdk_n3k_eal_opt *opt;
    size_t n3k_eal_param_cnt = 0;

    STAILQ_FOREACH(opt, &cfg->eal_opts, next)
    {
        n3k_eal_param_cnt++;
        if (opt->value != NULL) {
            n3k_eal_param_cnt++;
        }
    }

    return vr_eal_argc + n3k_eal_param_cnt;
}

static void
free_eal_opts(struct vr_dpdk_n3k_config *cfg)
{
    struct vr_dpdk_n3k_eal_opt *opt;

    while (!STAILQ_EMPTY(&cfg->eal_opts)) {
        opt = STAILQ_FIRST(&cfg->eal_opts);
        STAILQ_REMOVE_HEAD(&cfg->eal_opts, next);
        free(opt);
    }
}

static int
new_eal_opt(struct vr_dpdk_n3k_config *cfg, char *opt, char *value)
{
    struct vr_dpdk_n3k_eal_opt *eal_opt = malloc(sizeof(*eal_opt));
    if (!eal_opt) {
        RTE_LOG(
          ERR, VROUTER, "N3K config: Allocating memory for eal opt failed\n");
        return -ENOMEM;
    }

    RTE_LOG(INFO,
            VROUTER,
            "Passing %s%s%s to EAL\n",
            opt,
            value == NULL ? "" : " with value: ",
            value == NULL ? "" : value);

    eal_opt->opt = opt;
    eal_opt->value = value;

    STAILQ_INSERT_TAIL(&cfg->eal_opts, eal_opt, next);

    return 0;
}

static void
append_opts_to_eal_args(struct vr_dpdk_n3k_config *cfg,
                        size_t arg_pos,
                        char **argv)
{
    struct vr_dpdk_n3k_eal_opt *opt;

    STAILQ_FOREACH(opt, &cfg->eal_opts, next)
    {
        argv[arg_pos++] = opt->opt;
        if (opt->value) {
            argv[arg_pos++] = opt->value;
        }
    }
}

static char *
get_provided_opt(char **argv)
{
    return argv[optind - 1];
}

static char *
get_provided_opt_value(size_t argc, char **argv)
{
    bool option_has_value = (optind < argc) && (*argv[optind] != '-');

    return option_has_value ? argv[optind++] : NULL;
}

static int
handle_opt_eal(struct vr_dpdk_n3k_config *cfg, size_t vr_argc, char **vr_argv)
{
    if (optind >= vr_argc) {
        RTE_LOG(ERR, VROUTER, "N3K Config: Expected EAL opt, got nothing\n");
        return -EINVAL;
    }

    // Skip '--eal'
    optind++;

    char *opt = get_provided_opt(vr_argv);

    if (*opt != '-') {
        RTE_LOG(ERR, VROUTER, "N3K Config: Expected EAL option, got %s\n", opt);
        return -EINVAL;
    }

    char *value = get_provided_opt_value(vr_argc, vr_argv);

    return new_eal_opt(cfg, opt, value);
}

static int
handle_opt_whitelist(struct vr_dpdk_n3k_config *cfg,
                     size_t vr_argc,
                     char **vr_argv)
{
    static char whitelist_eal_opt[] = "--pci-whitelist";
    char *value = get_provided_opt_value(vr_argc, vr_argv);

    if (!value) {
        RTE_LOG(ERR, VROUTER, "N3K Config: Expected whitelist parameter\n");
        return -EINVAL;
    }

    if (strstr(value, "insert_type=flr-sim") != NULL) {
        vr_dpdk_n3k_service_core_flr_sim_enable();
    }

    return new_eal_opt(cfg, whitelist_eal_opt, value);
}

static unsigned int
get_subarg_len(char *ptrStr,
               unsigned int idx)
{
    unsigned int i = 0;
    char *strTmp = NULL;

    for(i=0; ptrStr; i++) {
        strTmp = strstr(ptrStr, ",");
        if(i == idx) {
            if(!strTmp) return strlen(ptrStr);
            else {
                return strTmp - ptrStr;
            }
        }
        if(!strTmp) break;

        ptrStr = strTmp + 1;
    }

    return 0;
}

static char*
get_subarg_val(char *ptrStr,
               unsigned int idx)
{
    unsigned int i = 0;
    char *strTmp = NULL;

    for(i=0; ptrStr; i++) {
        strTmp = strstr(ptrStr, ",");
        if(i == idx) {
            return ptrStr;
        }
        if(!strTmp) break;

        ptrStr = strTmp + 1;
    }

    return NULL;
}

static int
handle_opt_enable_n3k(struct vr_dpdk_n3k_config *cfg,
                      size_t vr_argc,
                      char **vr_argv)
{
    int i;
    unsigned int subLen = 0;
    char *tmpStr = get_provided_opt_value(vr_argc, vr_argv);

    if(!tmpStr) {
        RTE_LOG(ERR, VROUTER, "N3K Config: Missing representor name\n");
        return -EINVAL;
    }

    RTE_LOG(INFO, VROUTER, "N3K Config: Enabling N3K offloads\n");

    cfg->phy_representor_name_nbr = 0;
    for(i=0; i<REPRESENTORS_MAX_NUMBER; i++) {
        subLen = get_subarg_len(tmpStr, i);
        if(subLen) {
            subLen = (subLen>(RTE_DEV_NAME_MAX_LEN-1))?RTE_DEV_NAME_MAX_LEN-1:subLen;
            strncpy(cfg->phy_representor_name[i], get_subarg_val(tmpStr, i), subLen);
            cfg->phy_representor_name[i][subLen] = 0;
            cfg->phy_representor_name_nbr++;
        } else {
            break;
        }
        RTE_LOG(INFO, VROUTER, "N3K Config: Representor[%d]: %s\n", i, cfg->phy_representor_name[i]);
    }

    if(!strcmp("l3mh", cfg->phy_representor_name[0])) {
        cfg->multihoming_enabled = true;
        for(i=0; i<REPRESENTORS_MAX_NUMBER; i++) {
            snprintf(cfg->phy_representor_name[i], RTE_DEV_NAME_MAX_LEN, "net_n3k0_phy%d", i);
        }
        RTE_LOG(INFO, VROUTER, "N3K Config: Multihomming enabled\n");
    }

    return 0;
}

static int
handle_opt_no_drop_offload(struct vr_dpdk_n3k_config *cfg,
   __attribute__((unused)) size_t vr_argc,
   __attribute__((unused)) char **vr_argv)
{
    cfg->drop_offload_enabled = false;

    RTE_LOG(INFO, VROUTER, "N3K Config: Disabling drop offload\n");

    return 0;
}

static int
handle_opt_aging_lcore(struct vr_dpdk_n3k_config *cfg,
  __attribute__((unused)) size_t vr_argc,
  __attribute__((unused)) char **vr_argv)
{
    cfg->aging_service_core_enabled = true;

    RTE_LOG(INFO, VROUTER, "N3K Config: Enabling aging lcore\n");

    return 0;
}

static int
handle_opt_force_vdpa_mapping(struct vr_dpdk_n3k_config *cfg,
  __attribute__((unused)) size_t vr_argc,
  __attribute__((unused)) char **vr_argv)
{
    cfg->force_vdpa_mapping = true;

    RTE_LOG(INFO, VROUTER, "N3K Config: Forcing vDPA mapping\n");

    return 0;
}

struct vr_dpdk_n3k_option_handler n3k_options[] = {
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--enable_n3k",
                                           handle_opt_enable_n3k),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--no_drop_offload",
                                           handle_opt_no_drop_offload),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--aging_lcore",
                                           handle_opt_aging_lcore),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--eal", handle_opt_eal),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--whitelist", handle_opt_whitelist),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--force_vdpa_mapping",
                                           handle_opt_force_vdpa_mapping),
};

int
vr_dpdk_n3k_config_parse_opt(size_t vr_argc, char **vr_argv, char vr_opt)
{
    struct vr_dpdk_n3k_config *cfg = &n3k_config;
    int i = 0;
    char *opt_provided = get_provided_opt(vr_argv);

    for (; i < RTE_DIM(n3k_options); ++i) {
        struct vr_dpdk_n3k_option_handler *curr_opt = &n3k_options[i];
        bool opt_matched = strcmp(opt_provided, curr_opt->match_str) == 0;

        if (opt_matched) {
            return curr_opt->handler_routine(cfg, vr_argc, vr_argv);
        }
    }

    return -EINVAL;
}

int
vr_dpdk_n3k_config_get_updated_eal_args(
  size_t argc,
  char **argv,
  struct vr_dpdk_n3k_config_eal_args *updated_args)
{
    struct vr_dpdk_n3k_config *cfg = &n3k_config;
    size_t vr_eal_argc = get_argv_last_filled_pos(argc, argv) + 1;
    size_t new_size = get_n3k_eal_argc(cfg, vr_eal_argc);
    // Freed by caller
    char **updated_argv = malloc(sizeof(*updated_argv) * new_size);
    if (!updated_argv) {
        RTE_LOG(ERR,
                VROUTER,
                "N3K config: Allocating memory for updated eal args failed\n");
        return -ENOMEM;
    }

    memcpy(updated_argv, argv, vr_eal_argc * sizeof(*argv));

    append_opts_to_eal_args(cfg, vr_eal_argc, updated_argv);

    updated_args->argc = new_size;
    updated_args->argv = updated_argv;

    return 0;
}

static void
n3k_usage(void)
{
    RTE_LOG(
      INFO,
      VROUTER,
      "\n"
      "    --whitelist NAME            Add pci address to a PCI whitelist\n"
      "                                To use the device in vDPA mode: "
      "--whitelist <PCI>,vdpa=1\n"
      "                                equivalent of --eal --pci-whitelist "
      "...\n"
      "    --enable_n3k NAME           Use n3k specific callbacks\n"
      "                                it is needed to specify physical "
      "representor name here\n"
      "    --no_drop_offload           Do not offload drop flows to HW\n"
      "    --aging_lcore               Enable N3000 aging lcore\n"
      "    --eal                       Options for EAL must begin with --eal "
      "opt, e.g.\n"
      "                                --eal --log-level lib.eal:8\n"
      "   --force_vdpa_mapping         Assign random n3k VF for all vifs");
}

void
vr_dpdk_n3k_config_print_usage(void)
{
    n3k_usage();
}

void
vr_dpdk_n3k_config_init(void)
{
    return;
}

void
vr_dpdk_n3k_config_exit(void)
{
    struct vr_dpdk_n3k_config *cfg = &n3k_config;

    free_eal_opts(cfg);
}

bool
vr_dpdk_n3k_config_is_aging_service_core_enabled(void)
{
    return n3k_config.aging_service_core_enabled;
}

bool
vr_dpdk_n3k_config_is_n3k_enabled(void)
{
    return n3k_config.phy_representor_name_nbr != 0;
}

bool
vr_dpdk_n3k_config_is_drop_offload_enabled(void)
{
    return n3k_config.drop_offload_enabled;
}

bool
vr_dpdk_n3k_config_vdpa_mapping_enabled(void)
{
    return n3k_config.force_vdpa_mapping;
}

static int get_mac_by_name(const char *ptr_name, struct rte_ether_addr *ptr_mac_addr)
{
    int rc = -1;
    uint16_t port_id = 0;

    rc = rte_eth_dev_get_port_by_name(ptr_name, &port_id);
    if (!rc) {
        rc = rte_eth_macaddr_get(port_id, ptr_mac_addr);
    }

    return rc;
}

static const char* get_multihoming_representor(struct vr_interface *vif)
{
    int i;
    const char *representor_name = NULL;
    struct rte_ether_addr mac_addr;

    if( !vif ) {
        return NULL;
    }

    for(i=0; i<REPRESENTORS_MAX_NUMBER; i++) {
        if( !get_mac_by_name(n3k_config.phy_representor_name[i], &mac_addr) ) {
            if(!memcmp(vif->vif_mac, mac_addr.addr_bytes, sizeof(vif->vif_mac))) {
                representor_name = n3k_config.phy_representor_name[i];
                RTE_LOG(INFO, VROUTER, "Vif <%s> match to representor <%s>\n", vif->vif_name, representor_name);
                break;
            }
        }
    }

    return representor_name;
}

const char *
vr_dpdk_n3k_config_get_phy_repr_name(struct vr_interface *vif)
{
    const char *representor_name = NULL;

    if( n3k_config.multihoming_enabled ) {
        representor_name = get_multihoming_representor(vif);
    }
    else {
       representor_name = n3k_config.phy_representor_name[0];
    }

    return representor_name;
}
