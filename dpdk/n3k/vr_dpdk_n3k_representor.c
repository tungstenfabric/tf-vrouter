/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <errno.h>

#include "vr_dpdk.h"
#include "vr_interface.h"
#include "../vr_dpdk_representor.h"

#include "vr_dpdk_n3k_vhost.h"

#include "vr_dpdk_n3k_representor.h"
#include "vr_dpdk_n3k_representor_map.h"
#include "vr_dpdk_n3k_config.h"

#include <rte_port_ethdev.h>
#include <rte_pmd_n3k.h>

#define REPR_OP_OK       VR_DPDK_REPRESENTOR_OP_RES_HANDLED_OK
#define REPR_OP_ERR      VR_DPDK_REPRESENTOR_OP_RES_HANDLED_ERR
#define REPR_NOT_HANDLED VR_DPDK_REPRESENTOR_OP_RES_NOT_HANDLED

extern int vr_rxd_sz, vr_txd_sz;

struct rte_eth_conf n3k_representor_ethdev_conf = {
    .link_speeds = ETH_LINK_SPEED_AUTONEG,
    .rxmode = {
        .mq_mode            = ETH_MQ_RX_NONE,
        .max_rx_pkt_len     = VR_DEF_MAX_PACKET_SZ,
        .offloads = 0,
    },
    .txmode = {
        .mq_mode            = ETH_MQ_TX_NONE,
        .offloads = 0,
        .pvid               = 0,
        .hw_vlan_reject_tagged      = 0,
        .hw_vlan_reject_untagged    = 0,
        .hw_vlan_insert_pvid        = 0,
    },
    .fdir_conf = {
        .mode = RTE_FDIR_MODE_NONE,
        .status = RTE_FDIR_NO_REPORT_STATUS,
        .pballoc = RTE_FDIR_PBALLOC_64K,
        .drop_queue = 0,
        .flex_conf = {
        },
    },
    .intr_conf = {
        .lsc = 0, /* Enable Link status interrupts */
    },
};

/* RX ring configuration */
struct rte_eth_rxconf n3k_representor_rx_queue_conf = {
    .rx_thresh = {
        .pthresh = 8,
        .hthresh = 8,
        .wthresh = 4,
    },
    .rx_free_thresh = VR_DPDK_RX_BURST_SZ,
    .offloads = 0,
};

/* TX ring configuration */
struct rte_eth_txconf n3k_representor_tx_queue_conf = {
    .tx_thresh = {
        .pthresh = 32,
        .hthresh = 0,
        .wthresh = 0,
    },
    .offloads  = 0,
    .tx_free_thresh = 32,
    .tx_rs_thresh = 32,
};

/*
 * n3k_representor_rx_queue_release - releases a representor RX queue.
 *
 * Returns nothing.
 */
static void
n3k_representor_rx_queue_release(unsigned lcore_id,
        unsigned queue_index __attribute__((unused)), struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                        = &lcore->lcore_rx_queue_params[vif->vif_idx];
    /* free the queue */
    if (rx_queue->rxq_ops.f_free(rx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u representor device RX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(rx_queue->q_vif);
    memset(rx_queue, 0, sizeof(*rx_queue));
    memset(rx_queue_params, 0, sizeof(*rx_queue_params));
}

/*
 * n3k_representor_rx_queue_init - initializes representor's
 * RX queue.
 *
 * Returns a pointer to the RX queue on success, NULL otherwise.
 */
static struct vr_dpdk_queue *
n3k_representor_rx_queue_init(unsigned int lcore_id,
        struct vr_interface *vif, unsigned int queue_or_lcore_id)
{
    uint16_t rx_queue_id = queue_or_lcore_id;
    uint8_t port_id;
    unsigned int vif_idx = vif->vif_idx;
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

    struct vr_dpdk_ethdev *ethdev;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                    = &lcore->lcore_rx_queue_params[vif_idx];

    ethdev = (struct vr_dpdk_ethdev *)vif->vif_os;
    port_id = ethdev->ethdev_port_id;

    /* init queue */
    rx_queue->rxq_ops = rte_port_ethdev_reader_ops;
    rx_queue->q_queue_h = NULL;
    rx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct rte_port_ethdev_reader_params reader_params = {
        .port_id = port_id,
        .queue_id = rx_queue_id,
    };
    rx_queue->q_queue_h = rx_queue->rxq_ops.f_create(&reader_params, socket_id);
    if (rx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating eth device %" PRIu8
                " RX queue %" PRIu16 "\n", port_id, rx_queue_id);
        return NULL;
    }

    /* store queue params */
    rx_queue_params->qp_release_op = &n3k_representor_rx_queue_release;
    rx_queue_params->qp_ethdev.queue_id = rx_queue_id;
    rx_queue_params->qp_ethdev.port_id = port_id;

    return rx_queue;
}

/*
 * n3k_representor_tx_queue_release - releases a representor TX queue.
 *
 * Returns nothing.
 */
static void
n3k_representor_tx_queue_release(unsigned lcore_id, unsigned queue_index,
        struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue =
        &lcore->lcore_tx_queues[vif->vif_idx][queue_index];
    struct vr_dpdk_queue_params *tx_queue_params
        = &lcore->lcore_tx_queue_params[vif->vif_idx][queue_index];

    tx_queue->txq_ops.f_tx = NULL;
    rte_wmb();

    /* flush and free the queue */
    if (tx_queue->txq_ops.f_free(tx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u representor device TX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

/*
 * n3k_representor_tx_queue_init - initializes representor's
 * TX queue.
 *
 * Returns a pointer to the TX queue on success, NULL otherwise.
 */
static struct vr_dpdk_queue *
n3k_representor_tx_queue_init(unsigned int lcore_id,
        struct vr_interface *vif, unsigned int queue_or_lcore_id)
{
    uint8_t port_id;
    uint16_t tx_queue_id = queue_or_lcore_id;
    unsigned int vif_idx = vif->vif_idx, dpdk_queue_index;
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);

    struct vr_dpdk_ethdev *ethdev;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *tx_queue;
    struct vr_dpdk_queue_params *tx_queue_params;

    ethdev = (struct vr_dpdk_ethdev *)vif->vif_os;
    port_id = ethdev->ethdev_port_id;

    if (lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx]) {
        dpdk_queue_index =
            lcore->lcore_hw_queue_to_dpdk_index[vif->vif_idx][tx_queue_id];
    } else {
        dpdk_queue_index = 0;
    }

    tx_queue = &lcore->lcore_tx_queues[vif_idx][dpdk_queue_index];
    tx_queue_params = &lcore->lcore_tx_queue_params[vif_idx][dpdk_queue_index];

    /* init queue */
    tx_queue->txq_ops = rte_port_ethdev_writer_ops;
    tx_queue->q_queue_h = NULL;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* create the queue */
    struct rte_port_ethdev_writer_params writer_params = {
        .port_id = port_id,
        .queue_id = tx_queue_id,
        .tx_burst_sz = VR_DPDK_TX_BURST_SZ,
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params, socket_id);
    if (tx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating eth device %" PRIu8
                " TX queue %" PRIu16 "\n", port_id, tx_queue_id);
        return NULL;
    }

    /* store queue params */
    tx_queue_params->qp_release_op = &n3k_representor_tx_queue_release;
    tx_queue_params->qp_ethdev.queue_id = tx_queue_id;
    tx_queue_params->qp_ethdev.port_id = port_id;

    return tx_queue;
}

static enum vr_dpdk_representor_op_res
n3k_get_representor_name(struct vr_interface *vif, const char **repr_name)
{
    if (repr_name == NULL || vif == NULL) {
        RTE_LOG(ERR, VROUTER,
            "    %s(): invalid input arguments\n", __func__);

        return REPR_OP_ERR;
    }

    uint16_t port_id;
    int rc = rte_eth_dev_get_port_by_name((char *)vif->vif_name, &port_id);
    if (!rc) {
        *repr_name = (const char *)vif->vif_name;

        return REPR_OP_OK;
    }

    if (!vr_dpdk_n3k_config_vdpa_mapping_enabled()) {
        RTE_LOG(WARNING, VROUTER,
            "    %s(): could not find port_id by name %s; assuming non-vDPA vhost-user connection\n",
            __func__, vif->vif_name);

        return REPR_NOT_HANDLED;
    }

    *repr_name = vr_dpdk_n3k_representor_map_add(vif);
    if (*repr_name == NULL) {
        RTE_LOG(ERR, VROUTER,
            "    %s(): could not add representor mapping for vif: %s\n",
            __func__, vif->vif_name);

        return REPR_OP_ERR;
    }

    return REPR_OP_OK;
}

static enum vr_dpdk_representor_op_res
n3k_representor_init(struct vr_interface *vif, const char *repr_name)
{
    uint16_t port_id = 0;
    struct vr_dpdk_ethdev *ethdev = NULL;

    int rc = rte_eth_dev_get_port_by_name(repr_name, &port_id);
    if (rc) {
        RTE_LOG(ERR, VROUTER,
            "    %s(): could not find port_id by name %s\n",
            __func__, repr_name);
        return REPR_OP_ERR;
    }

    ethdev = &vr_dpdk.ethdevs[port_id];
    if (ethdev->ethdev_ptr != NULL) {
        RTE_LOG(ERR, VROUTER,
                "    %s(): representor %s with port id %"PRIu8" already added\n",
                __func__, repr_name, port_id);
        return REPR_OP_ERR;
    }
    ethdev->ethdev_port_id = port_id;
    ethdev->ethdev_vif_idx = vif->vif_idx;

    rc = vr_dpdk_ethdev_init(ethdev,
        &n3k_representor_ethdev_conf, &n3k_representor_tx_queue_conf, &n3k_representor_rx_queue_conf);
    if (rc) {
        RTE_LOG(ERR, VROUTER,
                "    %s(): error while initializing dpdk queues for %s\n",
                __func__, repr_name);
        return REPR_OP_ERR;
    }

    vif->vif_os = (void *)ethdev;
    //There should be also MAC assignment (see dpdk_vif_attach_ethdev),
    //but in the case of N3K slowpath
    //its dp-core responsibility to handle incorrect packets,
    //so MAC in this case is set by agent and left as is.

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
    enum vr_dpdk_representor_op_res res = n3k_get_representor_name(vif, &repr_name);
    if (res == REPR_OP_ERR) {
        RTE_LOG(ERR, VROUTER,
            "   %s(): couldn't get repr_name for vif: %s",
            __func__, vif ? (char*)vif->vif_name : "???");

        return res;
    } else if (res == REPR_NOT_HANDLED) {
        RTE_LOG(WARNING, VROUTER, "%s(): virtual vif %s not handled\n",
            __func__, vif->vif_name);

        return res;
    }

    res = n3k_representor_init(vif, repr_name);
    if (res == REPR_OP_ERR) {
        RTE_LOG(ERR, VROUTER,
            "    %s(): %s: error while initializing representor: vif: %s\n",
            __func__, repr_name, vif->vif_name);
        return res;
    }

    struct vr_dpdk_ethdev *ethdev = vif->vif_os;
    uint16_t port_id = ethdev->ethdev_port_id;

    int ret = vr_dpdk_interface_queue_setup(vif);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
                "    %s(): %s: error while initializing vrouter queues, vif: %s\n",
                __func__, repr_name, vif->vif_name);
        return REPR_OP_ERR;
    }

    ret = rte_eth_dev_start(port_id);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER,
                "    %s(): error starting vf representor %" PRIu8": %s (%d)\n",
                __func__, port_id, rte_strerror(-ret), -ret);
        return REPR_OP_ERR;
    }

    ret = vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
            ethdev->ethdev_nb_rx_queues, &n3k_representor_rx_queue_init,
            ethdev->ethdev_nb_tx_queues, &n3k_representor_tx_queue_init);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
                "    %s(): %s: error while scheduling an interface; vif: %s\n",
                __func__, repr_name, vif->vif_name);
        return REPR_OP_ERR;
    }

    int did = rte_pmd_n3k_get_vdpa_did_by_repr_name(repr_name);
    if (did >= 0) {
        RTE_LOG(INFO, VROUTER,
            "    %s(): adding vf representor %s: dataplane is vDPA; vif: %s \n",
            __func__, repr_name, vif->vif_name);

        return vr_dpdk_n3k_vhost_register(vif, did) ? REPR_OP_ERR : REPR_OP_OK;
    } else if (did < 0 && vr_dpdk_n3k_config_vdpa_mapping_enabled()) {
        RTE_LOG(ERR, VROUTER,
            "    %s(): vDPA forced, but cannot find corresponding vDPA device "
            "representor: %s, vif: %s\n",
            __func__, repr_name, vif->vif_name);

        return REPR_OP_ERR;
    }

    RTE_LOG(INFO, VROUTER,
        "    %s(): adding vf representor %s: dataplane is PCI passthru\n",
        __func__, repr_name);

    return REPR_OP_OK;
}

static int
n3k_representor_virtual_del(struct vr_interface *vif)
{
    uint16_t port_id;
    struct vr_dpdk_ethdev *ethdev;

    RTE_LOG(INFO, VROUTER, "Deleting vif %u virtual device\n", vif->vif_idx);

    if (vif->vif_os == NULL) {
        RTE_LOG(ERR, VROUTER,
                "    error deleting virtual dev: already removed\n");
        return -EEXIST;
    }
    vr_dpdk_n3k_vhost_unregister(vif);

    if (vr_dpdk_n3k_config_vdpa_mapping_enabled())
        vr_dpdk_n3k_representor_map_delete(vif);

    /* unschedule RX/TX queues */
    vr_dpdk_lcore_if_unschedule(vif);

    vr_dpdk_interface_queue_free(vif);

    ethdev = (struct vr_dpdk_ethdev *)(vif->vif_os);
    port_id = ethdev->ethdev_port_id;

    rte_eth_dev_stop(port_id);

    /* release eth device */
    return vr_dpdk_ethdev_release(ethdev);
}

static enum vr_dpdk_representor_op_res
n3k_representor_fabric_add(struct vr_interface *vif)
{
    strncpy((char *)vif->vif_name, vr_dpdk_n3k_config_get_phy_repr_name(),
        RTE_DIM(vif->vif_name) - 1);

    enum vr_dpdk_representor_op_res res = n3k_representor_init(vif, (const char *)vif->vif_name);
    if (res != REPR_OP_OK) {
        RTE_LOG(ERR, VROUTER,
            "    %s(): %s: error while initializing representor\n",
            __func__, vif->vif_name);
        return res;
    }

    struct vr_dpdk_ethdev *ethdev = vif->vif_os;
    uint16_t rep_port_id = ethdev->ethdev_port_id;

    int ret = vr_dpdk_interface_queue_setup(vif);
    if (ret < 0)
        return REPR_OP_ERR;

    ret = rte_eth_dev_start(rep_port_id);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "    error starting eth device %" PRIu8
                ": %s (%d)\n", rep_port_id, rte_strerror(-ret), -ret);
        return REPR_OP_ERR;
    }

    ret = vr_dpdk_ethdev_rss_init(ethdev);
    if (ret < 0)
        return REPR_OP_ERR;

    /* schedule RX/TX queues */
    ret = vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
        ethdev->ethdev_nb_rss_queues, &n3k_representor_rx_queue_init,
        ethdev->ethdev_nb_tx_queues, &n3k_representor_tx_queue_init);
    if (ret)
        return REPR_OP_ERR;
    return REPR_OP_OK;
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
            "    %s(): error: invalid arguments\n", __func__);
        return REPR_OP_ERR;
    }

    return vif_is_vm(vif) ? REPR_OP_OK : REPR_NOT_HANDLED;
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

    if (!vif) {
        RTE_LOG(ERR, VROUTER,
            "    %s(): error: invalid arguments\n",
            __func__);
        return REPR_OP_ERR;
    }

    if (vif_is_fabric(vif)) {
        return n3k_representor_fabric_add(vif);
    } else if (vif_is_vm(vif)) {
        return n3k_representor_virtual_add(vif);
    }
    return REPR_NOT_HANDLED;
}

static enum vr_dpdk_representor_op_res
vr_dpdk_n3k_representor_del(struct vr_interface *vif)
{
    /*
        For fabric vifs "default" deinitialization logic is used.
    */
    if (!vif) {
        RTE_LOG(ERR, VROUTER,
            "    %s(): error: invalid arguments\n", __func__);

        return REPR_OP_ERR;
    }

    if (vif_is_vm(vif)) {
        int ret = n3k_representor_virtual_del(vif);

        return ret == 0 ? REPR_OP_OK : REPR_OP_ERR;
    }

    return REPR_NOT_HANDLED;
}

static struct vr_dpdk_representor_ops n3k_representor_ops = {
    .vif_add = vr_dpdk_n3k_representor_add,
    .vif_del = vr_dpdk_n3k_representor_del,
    .stats_update = vr_dpdk_n3k_representor_stats_update
};

void
vr_dpdk_n3k_representor_init(void)
{
    if (!vr_dpdk_n3k_config_is_n3k_enabled()) {
        return;
    }

    vr_dpdk_n3k_representor_map_init();

    vr_dpdk_representor_ops_register(&n3k_representor_ops);
}

void
vr_dpdk_n3k_representor_exit(void)
{
    if (!vr_dpdk_n3k_config_is_n3k_enabled()) {
        return;
    }

    vr_dpdk_n3k_representor_map_exit();

    vr_dpdk_representor_ops_deregister();
}
