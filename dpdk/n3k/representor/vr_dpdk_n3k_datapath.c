/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_representor_impl.h"

#include "../vr_dpdk_n3k_config.h"

#include <vrouter.h>

#include <stdbool.h>

static const char *
datapath_type_to_string(enum vr_dpdk_n3k_datapath_type dp_type)
{
    switch(dp_type) {
    case N3K_DATAPATH_UNVERIFIED:
        return "PCI passthru or vDPA without mapping (vif name deduced to be representor name)";
    case N3K_DATAPATH_PCI_PASSTHRU:
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
vr_dpdk_n3k_datapath_deduce(struct vr_interface *vif)
{
    uint16_t port_id;
    int ret;
    enum vr_dpdk_n3k_datapath_type dp_type = N3K_DATAPATH_UNKNOWN;

    if (vif == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): invalid input arguments\n", __func__);

        dp_type = N3K_DATAPATH_UNKNOWN;
        goto out;
    }

    ret = rte_eth_dev_get_port_by_name((char *)vif->vif_name, &port_id);
    if (!ret) {
        dp_type = N3K_DATAPATH_UNVERIFIED;
        goto out;
    }

    if (!vr_dpdk_n3k_config_vdpa_mapping_enabled()) {
        RTE_LOG(WARNING, VROUTER,
            "%s(): could not find port_id by name %s\n",
            __func__, vif->vif_name);

        dp_type = N3K_DATAPATH_NO_VDPA_VHOST_USER;
        goto out;
    }

    return N3K_DATAPATH_MAPPED_VDPA;
out:
    n3k_datapath_print_info(vif, dp_type, __func__);

    return dp_type;
}

static bool
n3k_datapath_get_representor_name(struct vr_interface *vif, bool is_mapped,
                                  const char **name)
{
    struct vr_dpdk_n3k_representor_map_entry repr;
    const char *repr_name;
    bool datapath_already_setup = false;

    if (!is_mapped) {
        repr_name = (const char *)vif->vif_name;
        goto out;
    }

    repr = vr_dpdk_n3k_representor_map_get_entry_by_name(vif);
    if (repr.soft_reset) {
        repr_name = repr.repr_name;

        vr_dpdk_n3k_representor_map_entry_unmark_soft_reset(vif);

        RTE_LOG(INFO, VROUTER,
            "%s(vif: %s):  dataplane already setup(soft reset detected)\n",
            __func__, vif->vif_name);

        datapath_already_setup = true;
    } else {
        repr_name = vr_dpdk_n3k_representor_map_create_entry(vif);
        if (repr_name == NULL) {
            RTE_LOG(ERR, VROUTER,
                "%s(): could not create representor mapping for vif: %s\n",
                __func__, vif->vif_name);
            goto out;
        }

        repr = vr_dpdk_n3k_representor_map_get_entry_by_name(vif);
    }

    RTE_LOG(INFO, VROUTER, "%s(): mapped vif %u(name: %s, VF id: %"PRIu16", repr: %s)\n",
        __func__, vif->vif_idx, repr.vif_name, repr.id, repr_name);

out:
    *name = repr_name;

    return datapath_already_setup;
}

int
vr_dpdk_n3k_datapath_setup(struct vr_interface *vif, const char **repr_name)
{
    int ret = 0, did;
    enum vr_dpdk_n3k_datapath_type dp_type = N3K_DATAPATH_PCI_PASSTHRU;
    bool is_mapped = vr_dpdk_n3k_config_vdpa_mapping_enabled();
    const char *rname;
    bool datapath_already_setup = n3k_datapath_get_representor_name(vif, is_mapped, &rname);
    if (!rname) {
        ret = -EINVAL;
        dp_type = N3K_DATAPATH_UNKNOWN;
        goto out;
    }

    if (datapath_already_setup) {
        dp_type = N3K_DATAPATH_MAPPED_VDPA;
        goto out;
    }

    did = rte_pmd_n3k_get_vdpa_did_by_repr_name(rname);
    if (did >= 0) {
        dp_type = is_mapped ? N3K_DATAPATH_MAPPED_VDPA : N3K_DATAPATH_DETERMINISTIC_VDPA;

        ret = vr_dpdk_n3k_vhost_register(vif, did);
        if (ret) {
            RTE_LOG(ERR, VROUTER,
                "%s(): vDPA setup failed for representor: %s"
                ", vif: %s; ret: %s\n",
                __func__, rname, vif->vif_name, rte_strerror(-ret));
        }
    } else if (did < 0 && is_mapped) {
        RTE_LOG(ERR, VROUTER,
            "%s(): vDPA mapping enabled, but cannot find corresponding vDPA device "
            "representor: %s, vif: %s\n",
            __func__, rname, vif->vif_name);

        ret = -EINVAL;
    }

out:
    n3k_datapath_print_info(vif, dp_type, __func__);

    *repr_name = rname;
    return ret;
}

void
vr_dpdk_n3k_datapath_teardown(struct vr_interface *vif)
{
    struct vr_dpdk_n3k_representor_map_entry repr;
    uint16_t id;

    RTE_LOG(INFO, VROUTER, "%s(): vif %u: started\n",
        __func__, vif->vif_idx);

    if (!vr_dpdk_n3k_config_vdpa_mapping_enabled())
        goto out;

    repr = vr_dpdk_n3k_representor_map_get_entry_by_id(vif);
    id = repr.id;
    RTE_LOG(INFO, VROUTER, "%s(): vif %u(name: %s, VF id: %"PRIu16", repr: %s): started\n",
        __func__, vif->vif_idx, repr.vif_name, id, repr.repr_name);

    if (vr_shutdown_started) {
        RTE_LOG(INFO, VROUTER,
            "%s(vif: %u): dataplane teardown not needed (soft reset detected)\n",
            __func__, vif->vif_idx);
        vr_dpdk_n3k_representor_map_entry_mark_soft_reset(vif);
        goto out;
    }

    vr_dpdk_n3k_vhost_unregister(repr.vif_name);

    vr_dpdk_n3k_representor_map_delete_entry(vif);

out:
    RTE_LOG(INFO, VROUTER, "%s(): vif %u: finished\n",
        __func__, vif->vif_idx);
}
