/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_representor_impl.h"

#include <stdbool.h>

#include <rte_pmd_n3k.h>

#include "../vr_dpdk_n3k_config.h"

static const char *
datapath_type_to_string(enum vr_dpdk_n3k_datapath_type dp_type)
{
    switch(dp_type) {
    case N3K_DATAPATH_DETERMINISTIC_UNVERIFIED:
        return "PCI passthru or vDPA without mapping (vif name deduced to be representor name)";
    case N3K_DATAPATH_DETERMINISTIC_PCI_PASSTHRU:
        return "PCI passthru";
    case N3K_DATAPATH_DETERMINISTIC_VDPA:
        return "vDPA without mapping";
    case N3K_DATAPATH_MAPPED_VDPA:
        return "vDPA with mapping";
    case N3K_DATAPATH_NO_VDPA_VHOST_USER:
        return "directly connected to vRouter via vhost-user (not a representor)";
    default:
        break;
    }

    return "error? unknown datapath";
}

static void
n3k_datapath_print_info(struct vr_interface *vif,
                        enum vr_dpdk_n3k_datapath_type dp_type,
                        const char *caller)
{
    RTE_LOG(INFO, VROUTER, "%s(): %s: datapath is %s\n",
        caller, vif->vif_name, datapath_type_to_string(dp_type));
}

enum vr_dpdk_n3k_datapath_type
vr_dpdk_n3k_datapath_deduce(struct vr_interface *vif, const char **repr_name)
{
    uint16_t port_id;
    int ret;
    enum vr_dpdk_n3k_datapath_type dp_type = N3K_DATAPATH_UNKNOWN;

    if (repr_name == NULL || vif == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): invalid input arguments\n", __func__);

        dp_type = N3K_DATAPATH_UNKNOWN;
        goto found;
    }

    ret = rte_eth_dev_get_port_by_name((char *)vif->vif_name, &port_id);
    if (!ret) {
        *repr_name = (const char *)vif->vif_name;

        dp_type = N3K_DATAPATH_DETERMINISTIC_UNVERIFIED;
        goto found;
    }

    if (!vr_dpdk_n3k_config_vdpa_mapping_enabled()) {
        RTE_LOG(WARNING, VROUTER,
            "%s(): could not find port_id by name %s\n",
            __func__, vif->vif_name);

        dp_type = N3K_DATAPATH_NO_VDPA_VHOST_USER;
        goto found;
    }

    *repr_name = vr_dpdk_n3k_representor_map_create_mapping(vif);
    if (*repr_name == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): could not create representor mapping for vif: %s\n",
            __func__, vif->vif_name);

        dp_type = N3K_DATAPATH_UNKNOWN;
        goto found;
    }

    dp_type = N3K_DATAPATH_MAPPED_VDPA;
found:
    n3k_datapath_print_info(vif, dp_type, __func__);

    return dp_type;
}

int
vr_dpdk_n3k_datapath_setup(struct vr_interface *vif, const char *repr_name)
{
    enum vr_dpdk_n3k_datapath_type dp_type = N3K_DATAPATH_DETERMINISTIC_PCI_PASSTHRU;
    int ret = -EINVAL, did = rte_pmd_n3k_get_vdpa_did_by_repr_name(repr_name);
    bool is_mapped = vr_dpdk_n3k_config_vdpa_mapping_enabled();

    if (did >= 0) {
        dp_type = is_mapped ? N3K_DATAPATH_MAPPED_VDPA : N3K_DATAPATH_DETERMINISTIC_VDPA;

        ret = vr_dpdk_n3k_vhost_register(vif, did);
        if (ret) {
            RTE_LOG(ERR, VROUTER,
                "%s(): vDPA setup failed for representor: %s"
                ", vif: %s; ret: %s\n",
                __func__, repr_name, vif->vif_name, rte_strerror(-ret));
            return ret;
        }
    } else if (did < 0 && is_mapped) {
        RTE_LOG(ERR, VROUTER,
            "%s(): vDPA mapping enabled, but cannot find corresponding vDPA device "
            "representor: %s, vif: %s\n",
            __func__, repr_name, vif->vif_name);

        return ret;
    }

    n3k_datapath_print_info(vif, dp_type, __func__);

    return 0;
}

void
vr_dpdk_n3k_datapath_teardown(struct vr_interface *vif)
{
    vr_dpdk_n3k_vhost_unregister(vif);

    if (vr_dpdk_n3k_config_vdpa_mapping_enabled())
        vr_dpdk_n3k_representor_map_delete_mapping(vif);
}
