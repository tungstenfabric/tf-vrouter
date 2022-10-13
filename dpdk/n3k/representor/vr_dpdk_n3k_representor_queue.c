/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_representor_impl.h"

#include <rte_errno.h>
#include <rte_port_ethdev.h>

extern int vr_rxd_sz, vr_txd_sz;

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
        RTE_LOG(ERR, VROUTER, "error freeing lcore %u representor device RX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(rx_queue->q_vif);
    memset(rx_queue, 0, sizeof(*rx_queue));
    memset(rx_queue_params, 0, sizeof(*rx_queue_params));
}

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
        RTE_LOG(ERR, VROUTER, "error creating eth device %" PRIu8
                " RX queue %" PRIu16 "\n", port_id, rx_queue_id);
        return NULL;
    }

    /* store queue params */
    rx_queue_params->qp_release_op = &n3k_representor_rx_queue_release;
    rx_queue_params->qp_ethdev.queue_id = rx_queue_id;
    rx_queue_params->qp_ethdev.port_id = port_id;

    return rx_queue;
}

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
        RTE_LOG(ERR, VROUTER, "error freeing lcore %u representor device TX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
}

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
        RTE_LOG(ERR, VROUTER, "error creating eth device %" PRIu8
                " TX queue %" PRIu16 "\n", port_id, tx_queue_id);
        return NULL;
    }

    /* store queue params */
    tx_queue_params->qp_release_op = &n3k_representor_tx_queue_release;
    tx_queue_params->qp_ethdev.queue_id = tx_queue_id;
    tx_queue_params->qp_ethdev.port_id = port_id;

    return tx_queue;
}

static int
n3k_rx_queue_setup(struct vr_dpdk_ethdev *ethdev)
{
    int ret, qid = 0;
    uint8_t port_id = ethdev->ethdev_port_id;
    struct rte_mempool *mempool = vr_dpdk.rss_mempool;

    ethdev->ethdev_queue_states[qid] = VR_DPDK_QUEUE_RSS_STATE;

    ret = rte_eth_rx_queue_setup(port_id, qid, vr_rxd_sz,
        SOCKET_ID_ANY, &n3k_representor_rx_queue_conf, mempool);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "%s:() rte_eth_rx_queue_setup failed; port: %" PRIu8
                " : %s (%d)\n", __func__, port_id, rte_strerror(-ret), -ret);
        return ret;
    }

    rte_eth_dev_set_rx_queue_stats_mapping(port_id, qid, qid);

    ethdev->ethdev_mempools[qid] = mempool;

    return 0;
}

static int
n3k_tx_queue_setup(struct vr_dpdk_ethdev *ethdev)
{
    int ret, qid = 0;
    uint8_t port_id = ethdev->ethdev_port_id;

    ret = rte_eth_tx_queue_setup(port_id, qid, vr_txd_sz,
        SOCKET_ID_ANY, &n3k_representor_tx_queue_conf);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "%s:() rte_eth_tx_queue_setup failed; port: %" PRIu8
                " : %s (%d)\n", __func__, port_id, rte_strerror(-ret), -ret);
        return ret;
    }

    rte_eth_dev_set_tx_queue_stats_mapping(port_id, qid, qid);

    return 0;
}

int
vr_dpdk_n3k_representor_queue_setup(struct vr_dpdk_ethdev *ethdev)
{
    int ret;

    if (ethdev->ethdev_nb_rx_queues != 1 || ethdev->ethdev_nb_tx_queues != 1) {
        RTE_LOG(ERR, VROUTER, "%s(): invalid representor queue count: RXQ=%d TXQ=%d\n",
            __func__, ethdev->ethdev_nb_rx_queues, ethdev->ethdev_nb_tx_queues);
    }

    ret = n3k_rx_queue_setup(ethdev);
    if (ret) {
        RTE_LOG(ERR, VROUTER, "%s(): RX queue setup failed\n", __func__);
        return ret;
    }

    ret = n3k_tx_queue_setup(ethdev);
    if (ret) {
        RTE_LOG(ERR, VROUTER, "%s(): TX queue setup failed\n", __func__);
        return ret;
    }

    return 0;
}

int
vr_dpdk_n3k_representor_queue_lcore_interconnect(struct vr_interface *vif,
                                                 const char *repr_name)
{
    struct vr_dpdk_ethdev *ethdev = vif->vif_os;
    int ret;

    RTE_LOG(DEBUG, VROUTER, "%s(): started for vif: %s\n",
        __func__, vif->vif_name);

    ret = vr_dpdk_lcore_if_schedule(vif, vr_dpdk_lcore_least_used_get(),
            ethdev->ethdev_nb_rx_queues, &n3k_representor_rx_queue_init,
            ethdev->ethdev_nb_tx_queues, &n3k_representor_tx_queue_init);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): %s: interconnecting an interface with a lcore failed;"
            " vif: %s, ret: %s\n",
            __func__, repr_name, vif->vif_name, rte_strerror(-ret));
        return ret;
    }

    RTE_LOG(DEBUG, VROUTER, "%s(%s): succeeded\n",
        __func__, vif->vif_name);

    return 0;
}

void
vr_dpdk_n3k_representor_queue_lcore_disconnect(struct vr_interface *vif)
{
    vr_dpdk_lcore_if_unschedule(vif);
}
