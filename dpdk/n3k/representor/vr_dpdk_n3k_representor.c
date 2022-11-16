/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_representor.h"
#include "vr_dpdk_n3k_representor_impl.h"

#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include "../vr_dpdk_n3k_config.h"
#include "../../vr_dpdk_representor.h"

#define REPR_OP_OK          VR_DPDK_REPRESENTOR_OP_RES_HANDLED_OK
#define REPR_OP_ERR         VR_DPDK_REPRESENTOR_OP_RES_HANDLED_ERR
#define REPR_OP_NOT_HANDLED VR_DPDK_REPRESENTOR_OP_RES_NOT_HANDLED

static void
n3k_representor_set_vif_info(struct vr_interface *vif,
                             const char *repr_name, uint16_t port_id)
{
    vif->vif_os = (void *)&vr_dpdk.ethdevs[port_id];

    vif->vif_flags &= ~VIF_FLAG_TX_CSUM_OFFLOAD;
    vif->vif_flags &= ~VIF_FLAG_VLAN_OFFLOAD;
    vif->vif_flags &= ~VIF_FLAG_FILTERING_OFFLOAD;
    vif->vif_flags &= ~VIF_FLAG_MRG_RXBUF;
}

static enum vr_dpdk_representor_op_res
n3k_representor_vif_setup(struct vr_interface *vif,
                          const char* repr_name)
{
    uint16_t port_id;

    int ret = rte_eth_dev_get_port_by_name(repr_name, &port_id);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): could not find port_id by name %s\n",
            __func__, repr_name);
        return REPR_OP_ERR;
    }

    ret = vr_dpdk_n3k_representor_ethdev_init(vif, repr_name, port_id);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): could not initialize ethdev of %s\n; ret: %s",
            __func__, repr_name, rte_strerror(-ret));
        return REPR_OP_ERR;
    }

    //The name is misleading; this is not a queue setup but rather part of representor <-> lcore interconnection setup
    ret = vr_dpdk_interface_queue_setup(vif);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error preparing representor %s: %s (%d)\n",
            __func__, repr_name, rte_strerror(-ret), -ret);
        return REPR_OP_ERR;
    }

    n3k_representor_set_vif_info(vif, repr_name, port_id);

    ret = vr_dpdk_n3k_representor_queue_lcore_interconnect(vif, repr_name);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): could not initialize ethdev of %s\n; ret: %s",
            __func__, repr_name, rte_strerror(-ret));
        return REPR_OP_ERR;
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error starting representor %s: %s (%d)\n",
            __func__, repr_name, rte_strerror(-ret), -ret);
        return REPR_OP_ERR;
    }

    return REPR_OP_OK;
}

static int
n3k_representor_vif_teardown(struct vr_interface *vif)
{
    vr_dpdk_n3k_representor_queue_lcore_disconnect(vif);

    vr_dpdk_interface_queue_free(vif);

    return vr_dpdk_n3k_representor_ethdev_release(vif);
}

static enum vr_dpdk_representor_op_res
n3k_vf_datapath_setup(struct vr_interface *vif,
                      const char** repr_name)
{
    int ret = vr_dpdk_n3k_datapath_setup(vif, repr_name);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): %s(%s): failed\n",
            __func__, vif->vif_name, *repr_name);
        return REPR_OP_ERR;
    }

    RTE_LOG(DEBUG, VROUTER,
        "%s(): %s(%s): succeeded\n",
        __func__, vif->vif_name, *repr_name);

    return REPR_OP_OK;
}

/*
 * n3k_representor_virtual_add - add a virtual (representor) interface to vrouter.
 * Returns 0 on success, < 0 otherwise.
 */

static enum vr_dpdk_representor_op_res
n3k_representor_virtual_add(struct vr_interface *vif)
{
    const char *repr_name = NULL;
    enum vr_dpdk_representor_op_res res;
    enum vr_dpdk_n3k_datapath_type dp =
        vr_dpdk_n3k_datapath_deduce(vif);

    switch(dp) {
    case N3K_DATAPATH_UNKNOWN:
    case N3K_DATAPATH_NO_VDPA_VHOST_USER:
        RTE_LOG(WARNING, VROUTER, "%s(vif: %s): not handled\n",
            __func__, vif->vif_name);

        return REPR_OP_NOT_HANDLED;
    default:
        break;
    }

    res = n3k_vf_datapath_setup(vif, &repr_name);
    if (res != REPR_OP_OK)
        goto err;

    res = n3k_representor_vif_setup(vif, repr_name);
    if (res != REPR_OP_OK)
        goto err;

    RTE_LOG(DEBUG, VROUTER,
        "%s(vif: %s): configuration succeeded\n",
        __func__, vif->vif_name);

    return REPR_OP_OK;
err:
    RTE_LOG(ERR, VROUTER,
        "%s(vif: %s): configuration failed\n",
        __func__, vif->vif_name);

    return res;
}

static int
n3k_representor_virtual_del(struct vr_interface *vif)
{
    int ret;

    RTE_LOG(INFO, VROUTER, "%s(vif: %u): called\n",
        __func__, vif->vif_idx);

    if (vif->vif_os == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error deleting virtual dev: already removed\n", __func__);
        return -EEXIST;
    }

    vr_dpdk_n3k_datapath_teardown(vif);
    ret = n3k_representor_vif_teardown(vif);
    if (ret) {
        RTE_LOG(INFO, VROUTER, "%s(vif: %u): vif teardown failed\n",
            __func__, vif->vif_idx);
        return ret;
    }

    return 0;
}

static enum vr_dpdk_representor_op_res
n3k_representor_fabric_add(struct vr_interface *vif)
{
    const char *repr_name = vr_dpdk_n3k_config_get_phy_repr_name(vif);
    enum vr_dpdk_representor_op_res res =
        n3k_representor_vif_setup(vif, repr_name);
    if (res != REPR_OP_OK) {
        RTE_LOG(ERR, VROUTER,
            "%s(vif: %s): configuration failed\n",
            __func__, vif->vif_name);
        return res;
    }

    RTE_LOG(DEBUG, VROUTER,
        "%s(vif: %s): configuration succeeded\n",
        __func__, vif->vif_name);

    return REPR_OP_OK;
}

static int
n3k_representor_fabric_del(struct vr_interface *vif)
{
    RTE_LOG(INFO, VROUTER, "%s(vif: %u): deleting\n",
        __func__, vif->vif_idx);

    if (vif->vif_os == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(vif: %u): error deleting fabric dev: already removed\n",
            __func__, vif->vif_idx);
        return -EEXIST;
    }

    return n3k_representor_vif_teardown(vif);
}

static enum vr_dpdk_representor_op_res
vr_dpdk_n3k_representor_stats_update(struct vr_interface *vif)
{
    /* Here we tell vRouter that, when N3K offload is enabled,
    it should treat virtual vif as interface which is implemented as ethdev,
    which will result in vRouter calling ethdev API to get statistics from VF
    representor.
    */

    if (!vif) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error: invalid arguments\n", __func__);
        return REPR_OP_ERR;
    }

    return vif_is_vm(vif) ? REPR_OP_OK : REPR_OP_NOT_HANDLED;
}

static enum vr_dpdk_representor_op_res
vr_dpdk_n3k_representor_add(struct vr_interface *vif)
{
    /*
        If dpdk_vif_add fails then dpdk_vif_del is called by Agent,
        thus n3k_representor_*_add functions do not have error handling logic.
        By returning VR_DPDK_REPRESENTOR_OP_RES_HANDLED_ERR
        here if n3k_representor_*_add failed, we assure that
        n3k_representor_*_del is called.
    */

    RTE_LOG(DEBUG, VROUTER, "%s(vif: %s): called\n",
        __func__, vif->vif_name ? (char*)vif->vif_name : "(unknown name)");

    if (!vif) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error: invalid arguments\n",
            __func__);
        return REPR_OP_ERR;
    }

    if (vif_is_fabric(vif)) {
        return n3k_representor_fabric_add(vif);
    } else if (vif_is_vm(vif)) {
        return n3k_representor_virtual_add(vif);
    }

    return REPR_OP_NOT_HANDLED;
}

static enum vr_dpdk_representor_op_res
vr_dpdk_n3k_representor_del(struct vr_interface *vif)
{
    int ret = -1;
    enum vr_dpdk_representor_op_res res = REPR_OP_NOT_HANDLED;

    if (!vif) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error: invalid arguments\n", __func__);

        return REPR_OP_ERR;
    }

    RTE_LOG(DEBUG, VROUTER, "%s(vif: %s): called\n",
        __func__, vif->vif_name ? (char*)vif->vif_name : "(unknown name)");

    if (vif_is_fabric(vif)) {
        ret = n3k_representor_fabric_del(vif);
    } else if (vif_is_vm(vif)) {
        ret = n3k_representor_virtual_del(vif);
    }

    if (ret != -1) {
        res = ret ? REPR_OP_ERR : REPR_OP_OK;
    }

    return res;
}

static struct vr_dpdk_representor_ops n3k_representor_ops = {
    .vif_add = vr_dpdk_n3k_representor_add,
    .vif_del = vr_dpdk_n3k_representor_del,
    .stats_update = vr_dpdk_n3k_representor_stats_update
};

void
vr_dpdk_n3k_representor_init(void)
{
    vr_dpdk_n3k_representor_map_init();

    vr_dpdk_n3k_link_init();

    vr_dpdk_n3k_vhost_init();

    vr_dpdk_representor_ops_register(&n3k_representor_ops);
}

void
vr_dpdk_n3k_representor_exit(void)
{
    vr_dpdk_representor_ops_deregister();

    vr_dpdk_n3k_vhost_exit();

    vr_dpdk_n3k_link_exit();

    vr_dpdk_n3k_representor_map_exit();
}
