/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_CONFIG_H__
#define __VR_DPDK_N3K_CONFIG_H__

#include <stddef.h>
#include <stdbool.h>

struct vr_dpdk_n3k_config_eal_args {
    char **argv;
    size_t argc;
};

int vr_dpdk_n3k_config_parse_opt(size_t, char **, char);
int vr_dpdk_n3k_config_get_updated_eal_args(size_t, char **, struct vr_dpdk_n3k_config_eal_args *);
void vr_dpdk_n3k_config_exit(void);
void vr_dpdk_n3k_config_init(void);
void vr_dpdk_n3k_config_print_usage(void);

bool vr_dpdk_n3k_config_is_aging_service_core_enabled(void);
bool vr_dpdk_n3k_config_is_n3k_enabled(void);
bool vr_dpdk_n3k_config_is_drop_offload_enabled(void);
bool vr_dpdk_n3k_config_vdpa_mapping_enabled(void);
const char *vr_dpdk_n3k_config_get_phy_repr_name(struct vr_interface *vif);

#endif //__VR_DPDK_N3K_CONFIG_H__
