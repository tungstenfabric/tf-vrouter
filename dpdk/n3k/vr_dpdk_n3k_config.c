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

#include "vr_dpdk.h"
#include "vr_dpdk_n3k_config.h"

#define VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER(match, routine)                 \
    {                                                                          \
        .match_str = (match), .handler_routine = (routine)                     \
    }

struct vr_dpdk_n3k_eal_opt {
    STAILQ_ENTRY(vr_dpdk_n3k_unrecognized_opt) next;

    char *opt;
    char *value;
};

STAILQ_HEAD(vr_dpdk_n3k_eal_opts, vr_dpdk_n3k_eal_opt);

struct vr_dpdk_n3k_config {
    char *pp_representor_name;
    bool drop_offload_enabled;
    bool aging_service_core_enabled;
    struct vr_dpdk_n3k_eal_opts eal_opts;
};

struct vr_dpdk_n3k_config n3k_config = { .pp_representor_name = NULL,
                                         .drop_offload_enabled = true,
                                         .aging_service_core_enabled = false,
                                         .eal_opts = STAILQ_HEAD_INITIALIZER(
                                           n3k_config.eal_opts) };

typedef int (*option_handler_t)(struct vr_dpdk_n3k_config *, size_t, char **);

struct vr_dpdk_n3k_option_handler {
    const char *match_str;
    option_handler_t handler_routine;
};

// TODO: remove after corresponding logic is moved from DPDK common code
extern unsigned int disable_drop_offloads;
int enable_n3k = 0;
char *n3k_phy_representor_name = NULL;

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
    size_t eal_opt_sz = 0;

    STAILQ_FOREACH(opt, &cfg->eal_opts, next)
    {
        eal_opt_sz++;
        if (opt->value != NULL) {
            eal_opt_sz++;
        }
    }

    return vr_eal_argc + eal_opt_sz;
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

    return new_eal_opt(cfg, whitelist_eal_opt, value);
}

static int
handle_opt_enable_n3k(__attribute__((unused)) struct vr_dpdk_n3k_config *cfg,
                      size_t vr_argc,
                      char **vr_argv)
{
    // n3k_config.pp_representor_name = optarg;
    n3k_phy_representor_name = get_provided_opt_value(vr_argc, vr_argv);

    if (!n3k_phy_representor_name) {
        RTE_LOG(ERR, VROUTER, "N3K Config: Missing representor name\n");
        return -EINVAL;
    }

    n3k_config.pp_representor_name = n3k_phy_representor_name;
    enable_n3k = 1;

    RTE_LOG(INFO, VROUTER, "N3K Config: Enabling N3K offloads\n");

    return 0;
}

static int
handle_opt_no_drop_offload(
  __attribute__((unused)) struct vr_dpdk_n3k_config *cfg,
  __attribute__((unused)) size_t vr_argc,
  __attribute__((unused)) char **vr_argv)
{
    // n3k_config.drop_offload_enabled = false;
    disable_drop_offloads = 1;

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

struct vr_dpdk_n3k_option_handler n3k_options[] = {
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--enable_n3k",
                                           handle_opt_enable_n3k),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--no_drop_offload",
                                           handle_opt_no_drop_offload),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--aging_lcore",
                                           handle_opt_aging_lcore),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--eal", handle_opt_eal),
    VR_DPDK_N3K_OPTION_HANDLER_INITIALIZER("--whitelist", handle_opt_whitelist)
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
    size_t argv_last_filled_pos = get_argv_last_filled_pos(argc, argv);
    size_t new_size = get_n3k_eal_argc(cfg, argv_last_filled_pos + 1);
    // Freed by caller
    char **updated_argv = malloc(sizeof(*updated_argv) * new_size);
    if (!updated_argv) {
        RTE_LOG(ERR,
                VROUTER,
                "N3K config: Allocating memory for updated eal args failed\n");
        return -ENOMEM;
    }

    memcpy(updated_argv, argv, (argv_last_filled_pos + 1) * sizeof(*argv));

    append_opts_to_eal_args(cfg, argv_last_filled_pos, updated_argv);

    updated_args->argc = new_size;
    updated_args->argv = updated_argv;

    return 0;
}

static void
n3k_usage(__attribute__((unused)) const char *prgname)
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
      "                                --eal --log-level lib.eal:8\n");
}

void
vr_dpdk_n3k_config_print_usage(void)
{
    n3k_usage(NULL);
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
    return n3k_config.pp_representor_name != NULL;
}
