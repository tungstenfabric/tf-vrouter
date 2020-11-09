/*
 * vr_dpdk_virtio.c - implements DPDK forwarding infrastructure for
 * virtio interfaces. The virtio data structures are setup by the user
 * space vhost server.
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#include "vr_dpdk.h"
#include "vr_dpdk_virtio.h"
#include "vr_uvhost_client.h"

#include <linux/virtio_net.h>
#include <sys/eventfd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <rte_vhost.h>

#include <rte_malloc.h>
#include <rte_memcpy.h>

#define VIRTIO_HDR_MRG_RXBUF 1

// need to modify the max clients to same as that of MAX_VHOST_DEVICE
void *vr_dpdk_vif_clients[VR_MAX_INTERFACES];

vr_dpdk_virtioq_t vr_dpdk_virtio_rxqs[VR_MAX_INTERFACES][VR_DPDK_VIRTIO_MAX_QUEUES];
vr_dpdk_virtioq_t vr_dpdk_virtio_txqs[VR_MAX_INTERFACES][VR_DPDK_VIRTIO_MAX_QUEUES];

static int dpdk_virtio_from_vm_rx(void *port, struct rte_mbuf **pkts,
                                  uint32_t max_pkts);
static int dpdk_virtio_to_vm_tx(void *port, struct rte_mbuf *pkt);
static int dpdk_virtio_to_vm_flush(void *port);
static int dpdk_virtio_writer_stats_read(void *port,
                                            struct rte_port_out_stats *stats,
                                            int clear);
#if 0
// place holder for stats
static int dpdk_virtio_reader_stats_read(void *port,
                                            struct rte_port_in_stats *stats,
                                            int clear);
#endif
/*
 * Virtio writer
 */
struct dpdk_virtio_writer {
    struct rte_port_out_stats stats;
    /* extra statistics */
    uint64_t nb_syscalls;
    /* last packet TX */
    uint64_t last_pkt_tx;
    /* last TX flush */
    uint64_t last_pkt_tx_flush;

    vr_dpdk_virtioq_t *tx_virtioq;
    struct rte_mbuf *tx_buf[VR_DPDK_VIRTIO_TX_BURST_SZ];
    /* Total number of mbuf chains
     * Say if a mbuf chain contains 10 segments, it is counted as 1
     */
    uint32_t tx_buf_count;
    /* Total number of mbufs in all the chains */
    uint32_t tx_mbufs;
};

struct dpdk_virtio_writer_params {
    /* virtio TX queue pointer */
    vr_dpdk_virtioq_t *tx_virtioq;
};

#ifdef NAREN_VM_SHUTDOWN
/*
 * vr_dpdk_virtio_stop - stop the virtio interface.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_virtiotop(unsigned int vif_idx)
{
    int i;
    vr_dpdk_virtioq_t *vq;

    if (vif_idx >= VR_MAX_INTERFACES) {
        return -1;
    }

    /* Disable and reset all the virtio queues. */
    for (i = 0; i < VR_DPDK_VIRTIO_MAX_QUEUES*2; i++) {
        if (i & 1) {
            vq = &vr_dpdk_virtio_rxqs[vif_idx][i/2];
        } else {
            vq = &vr_dpdk_virtio_txqs[vif_idx][i/2];
        }

        if (vq->vdv_ready_state != VQ_NOT_READY) {
            vr_dpdk_set_virtq_ready(vif_idx, i, VQ_NOT_READY);
            rte_wmb();
            synchronize_rcu();
            /*
             * TODO: code duplication to minimize the changes.
             * See vr_dpdk_virtio_get_vring_base().
             */
            vq->vdv_desc = NULL;
            if (vq->vdv_callfd) {
                close(vq->vdv_callfd);
                vq->vdv_callfd = 0;
            }
        }
    }

    return 0;
}
#endif

static void *
dpdk_virtio_writer_create(void *params, int socket_id)
{
    struct dpdk_virtio_writer_params *conf =
            (struct dpdk_virtio_writer_params *) params;
    struct dpdk_virtio_writer *port;

    /* Check input parameters */
    if (conf == NULL) {
        RTE_LOG(ERR, PORT, "%s: Invalid input parameters\n", __func__);
        return NULL;
    }

    /* Memory allocation */
    port = rte_zmalloc_socket("PORT", sizeof(*port),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
        return NULL;
    }

    /* Initialization */
    port->tx_virtioq = conf->tx_virtioq;

    return port;
}

static int
dpdk_virtio_writer_free(void *port)
{
    vr_dpdk_virtioq_t *tx_virtioq;

    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: port is NULL\n", __func__);
        return -EINVAL;
    }

    tx_virtioq = ((struct dpdk_virtio_writer *)port)->tx_virtioq;

    /* reset the virtio */
    memset(tx_virtioq, 0, sizeof(vr_dpdk_virtioq_t));
    tx_virtioq->vdv_vid = -1;
    rte_free(port);

    return 0;
}

struct rte_port_out_ops vr_dpdk_virtio_writer_ops = {
    .f_create = dpdk_virtio_writer_create,
    .f_free = dpdk_virtio_writer_free,
    .f_tx = dpdk_virtio_to_vm_tx,
    .f_tx_bulk = NULL, /* TODO: not implemented */
    .f_flush = dpdk_virtio_to_vm_flush,
    .f_stats = dpdk_virtio_writer_stats_read
};

/*
 * Virtio reader
 */
struct dpdk_virtio_reader {
    struct rte_port_in_stats stats;
    /* extra statistics */
    uint64_t nb_syscalls;
    uint64_t nb_nombufs;

    vr_dpdk_virtioq_t *rx_virtioq;
};

struct dpdk_virtio_reader_params {
    /* virtio RX queue pointer */
    vr_dpdk_virtioq_t *rx_virtioq;
};

static void *
dpdk_virtio_reader_create(void *params, int socket_id)
{
    struct dpdk_virtio_reader_params *conf =
            (struct dpdk_virtio_reader_params *) params;
    struct dpdk_virtio_reader *port;

    /* Check input parameters */
    if (conf == NULL) {
        RTE_LOG(ERR, PORT, "%s: Invalid input parameters\n", __func__);
        return NULL;
    }

    /* Memory allocation */
    port = rte_zmalloc_socket("PORT", sizeof(*port),
            RTE_CACHE_LINE_SIZE, socket_id);
    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: Failed to allocate port\n", __func__);
        return NULL;
    }

    /* Initialization */
    port->rx_virtioq = conf->rx_virtioq;

    return port;
}

static int
dpdk_virtio_reader_free(void *port)
{
    vr_dpdk_virtioq_t *rx_virtioq;

    if (port == NULL) {
        RTE_LOG(ERR, PORT, "%s: port is NULL\n", __func__);
        return -EINVAL;
    }

    rx_virtioq = ((struct dpdk_virtio_reader *)port)->rx_virtioq;

    /* reset the virtio */
    memset(rx_virtioq, 0, sizeof(vr_dpdk_virtioq_t));
    rx_virtioq->vdv_vid = -1;

    rte_free(port);

    return 0;
}

    // naren design getting for stats
struct rte_port_in_ops vr_dpdk_virtio_reader_ops = {
    .f_create = dpdk_virtio_reader_create,
    .f_free = dpdk_virtio_reader_free,
    .f_rx = dpdk_virtio_from_vm_rx,
    .f_stats = NULL 
    // naren stats TBD dpdk_virtio_reader_stats_read
};

/*
 * vr_dpdk_vrtio_uvh_get_blk_size - set the block size of fd.
 * On error -1 is returned, otherwise 0.
 */
int
vr_dpdk_virtio_uvh_get_blk_size(int fd, uint64_t *const blksize)
{
    struct stat fd_stat;
    int ret;
    memset(&fd_stat, 0, sizeof(stat));

    ret = fstat(fd, &fd_stat);
    if (!ret){
        *blksize = (uint64_t)fd_stat.st_blksize;
    } else {
        RTE_LOG_DP(DEBUG, UVHOST, "Error getting file status for FD %d: %s (%d)\n",
                fd, strerror(errno), errno);
    }

    return ret;
}

/*
 * vr_dpdk_virtio_nrxqs - returns the number of receives queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_nrxqs(struct vr_interface *vif)
{
    return vr_dpdk.nb_fwd_lcores;
}

/*
 * vr_dpdk_virtio_ntxqs - returns the number of transmit queues for a virtio
 * interface.
 */
uint16_t
vr_dpdk_virtio_ntxqs(struct vr_interface *vif)
{
    return vr_dpdk.nb_fwd_lcores;
}

static unsigned int vif_rx_queue_lcore[VR_MAX_INTERFACES][VR_MAX_INTERFACES];

/*
 * dpdk_virtio_rx_queue_release - releases a virtio RX queue.
 *
 * Returns nothing.
 */
static void
dpdk_virtio_rx_queue_release(unsigned lcore_id,
        unsigned queue_index __attribute__((unused)),
        struct vr_interface *vif)
{
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif->vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params
                        = &lcore->lcore_rx_queue_params[vif->vif_idx];
    /* free the queue */
    if (rx_queue->rxq_ops.f_free(rx_queue->q_queue_h)) {
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u virtio device RX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(rx_queue->q_vif);
    memset(rx_queue, 0, sizeof(*rx_queue));
    memset(rx_queue_params, 0, sizeof(*rx_queue_params));
    // naren implement reset fn appropriately
    rx_queue->vr_vid = -1;

}

struct vr_dpdk_queue *
vr_dpdk_virtio_rx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                                      unsigned int queue_or_lcore_id)
{

    uint16_t queue_id = queue_or_lcore_id;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);
    unsigned int vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *rx_queue = &lcore->lcore_rx_queues[vif_idx];
    struct vr_dpdk_queue_params *rx_queue_params =
        &lcore->lcore_rx_queue_params[vif_idx];

    /* Check input parameters */
    if (queue_id >= vr_dpdk_virtio_nrxqs(vif)) {
        RTE_LOG(ERR, VROUTER, "    error creating virtio device %s RX queue %"
            PRIu16 "\n", vif->vif_name, queue_id);
        return NULL;
    }

    /* init queue */
    rx_queue->rxq_ops = vr_dpdk_virtio_reader_ops;
    rx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);
// naren 
// IF_NAME_SZ, MAX_VHOST_DEVICE   defined in (vhost.h)
    /* init virtio queue */
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_ready_state = VQ_NOT_READY;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_vid = -1;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_vif_idx = vif->vif_idx;
    vr_dpdk_virtio_rxqs[vif_idx][queue_id].vdv_queue_id = queue_id;

    /* create the queue */
    struct dpdk_virtio_reader_params reader_params = {
        .rx_virtioq = &vr_dpdk_virtio_rxqs[vif_idx][queue_id],
    };
#if 1
    // NAREN TBD
    // actual implementation this alloc not required
    // it is not to be used in upstream dpdk vhost-user
    rx_queue->q_queue_h = rx_queue->rxq_ops.f_create(&reader_params, socket_id);
    if (rx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating virtio device %s RX queue %"
            PRIu16 "\n", vif->vif_name, queue_id);
        return NULL;
    }
#endif
    rx_queue->vring_queue_id = queue_id;
    rx_queue->vr_vid = -1;
    /* store queue params */
    rx_queue_params->qp_release_op = &dpdk_virtio_rx_queue_release;

    /* save the lcore serving the queue for later enabling/disabling */
    vif_rx_queue_lcore[vif_idx][queue_id] = lcore_id;

    return rx_queue;
}

/*
 * dpdk_virtio_tx_queue_release - releases a virtio TX queue.
 *
 * Returns nothing.
 */
static void
dpdk_virtio_tx_queue_release(unsigned lcore_id, unsigned queue_index,
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
        RTE_LOG(ERR, VROUTER, "    error freeing lcore %u virtio device TX queue\n",
                    lcore_id);
    }

    /* reset the queue */
    vrouter_put_interface(tx_queue->q_vif);
    memset(tx_queue, 0, sizeof(*tx_queue));
    memset(tx_queue_params, 0, sizeof(*tx_queue_params));
#if 1
    // naren implement reset fn appropriately
    tx_queue->vr_vid = -1;
#endif
}

/*
 * vr_dpdk_virtio_tx_queue_init - initializes a virtio TX queue.
 *
 * Returns a pointer to the TX queue on success, NULL otherwise.
 */
struct vr_dpdk_queue *
vr_dpdk_virtio_tx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int queue_or_lcore_id)
{
    uint16_t queue_id = queue_or_lcore_id;
    struct vr_dpdk_lcore *lcore = vr_dpdk.lcores[lcore_id];
    const unsigned int socket_id = rte_lcore_to_socket_id(lcore_id);
    unsigned int vif_idx = vif->vif_idx;
    struct vr_dpdk_queue *tx_queue = &lcore->lcore_tx_queues[vif_idx][0];
    struct vr_dpdk_queue_params *tx_queue_params
                = &lcore->lcore_tx_queue_params[vif_idx][0];

    /* Check input parameters */
    /* virtio TX is thread safe, so just use one of the rings */
    queue_id = queue_id % vr_dpdk_virtio_ntxqs(vif);

    /* init queue */
    tx_queue->txq_ops = vr_dpdk_virtio_writer_ops;
    tx_queue->q_vif = vrouter_get_interface(vif->vif_rid, vif_idx);

    /* init virtio queue */
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_ready_state = VQ_NOT_READY;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_vif_idx = vif->vif_idx;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_vid = -1;
    vr_dpdk_virtio_txqs[vif_idx][queue_id].vdv_queue_id = queue_id;
    // naren explicitly set here the queue_id for queue number 0
     vr_dpdk_virtio_txqs[vif_idx][0].vdv_vid = -1;
     vr_dpdk_virtio_txqs[vif_idx][0].vdv_queue_id = queue_id;

    /* create the queue */
    struct dpdk_virtio_writer_params writer_params = {
        /*
         * Always initialize each lcore's tx_queue with virtio queue number 0.
         * If there are more queues, they will be enabled later via
         * VHOST_USER_SET_VRING_ENABLE message.
         */
        .tx_virtioq = &vr_dpdk_virtio_txqs[vif_idx][0],
    };
    tx_queue->q_queue_h = tx_queue->txq_ops.f_create(&writer_params, socket_id);
    if (tx_queue->q_queue_h == NULL) {
        RTE_LOG(ERR, VROUTER, "    error creating virtio device %s TX queue %"
            PRIu16 "\n", vif->vif_name, queue_id);
        return NULL;
    }

    /* store queue params */
    tx_queue_params->qp_release_op = &dpdk_virtio_tx_queue_release;

    return tx_queue;
}

struct dpdk_virtio_tx_queue_set_params {
    unsigned int vif_id;
    unsigned int vif_gen;
    unsigned int queue_id;
};

static unsigned int vif_lcore_tx_queue[VR_MAX_INTERFACES][VR_MAX_CPUS_DPDK];
static unsigned int vif_tx_queues_enabled[VR_MAX_INTERFACES];

/*
 * Enable or disable given queue for a vif.
 *
 * In current vRouter design, every lcore that can send packets has to have a
 * TX queue available for every existing vif. It is because we do not know
 * which lcore wil eventually send the packet, and thus each has to have a
 * queue to use.
 *
 * If VM requests more than one virtio queue, then we distribute them among the
 * forwarding lcores as evenly as possible.
 *
 * The entire process (this function, which sends commands to other lcores and
 * then vr_dpdk_virtio_tx_queue_set(), which is called from the destination
 * lcores' main loop) works fine as long as the QEMU enables/disables each
 * queues in ascending order. For example, if the maximal number of queues is
 * 4, and inside a VM ethtool -L eth0 combined 2 is issued, the QEMU will send
 * the following messages:
 * 1. Enable queue 0.
 * 2. Enable queue 1.
 * 3. Disable queue 2.
 * 4. Disable queue 3.
 *
 * TODO: Remove the above assumption as there is no guarantee that QEMU will
 * always work as described.
 */
void
vr_dpdk_virtio_tx_queue_enable_disable(unsigned int vif_id,
                                       unsigned int vif_gen,
                                       unsigned int queue_id,
                                       bool enable)
{
    unsigned int lcore_id;
    unsigned int starting_lcore;
    struct dpdk_virtio_tx_queue_set_params *arg;
    unsigned int qid;
    unsigned int queue_num;

    /* If command is 'disable', we enable all lower numbered queues */
    if (!enable)
        queue_num = queue_id - 1;
    else
        queue_num = queue_id;

    /*
     * Subsequent 'disable' commands are ignored. For example if we enabled
     * queues 0 and 1, then all higher queues (2, 3, ..) had already been
     * disabled. Thus we ignore the 'disable' request for them
     */
    if (!enable && queue_num > vif_tx_queues_enabled[vif_id])
        return;

    /*
     * Each lcore that does tx has to have a queue assigned for every
     * interface. We assign queue 0 for pkt and netlink lcores. All
     * other queues (including queue 0) are distributed among forwarding
     * lcores.
     */
    if (queue_id == 0)
        starting_lcore = VR_DPDK_PACKET_LCORE_ID;
    else
        starting_lcore = VR_DPDK_FWD_LCORE_ID;

    for (lcore_id = starting_lcore, qid = 0; lcore_id < vr_dpdk.nb_fwd_lcores +
            VR_DPDK_FWD_LCORE_ID; ++lcore_id) {

        /*
         * Send cmd to destination lcore only if it has different queue enabled
         * curently.
         */
        if (vif_lcore_tx_queue[vif_id][lcore_id - VR_DPDK_PACKET_LCORE_ID] !=
                qid) {
            vif_lcore_tx_queue[vif_id][lcore_id - VR_DPDK_PACKET_LCORE_ID] =
                    qid;

            arg = rte_malloc("virtio_tx_queue_set", sizeof(*arg), 0);

            arg->vif_id = vif_id;
            arg->queue_id = qid;
            arg->vif_gen = vif_gen;

            vr_dpdk_lcore_cmd_post(lcore_id, VR_DPDK_LCORE_TX_QUEUE_SET_CMD,
                                   (uint64_t)arg);
        }

        ++qid;
        qid %= queue_num + 1;
    }

    /* Save current number of TX queues enabled for vif */
    vif_tx_queues_enabled[vif_id] = queue_num;
}

/*
 * Assign given virtio queue to vRouter's dpdk (per lcore) tx queue.
 *
 * The assignment is done by setting correct virtio queue pointer in the
 * lcore's tx queue handler.
 *
 * This function is called only from the main loops of the lcores that have TX
 * queues (packet lcore, netlink lcore, forwarding lcores).
 */
void
vr_dpdk_virtio_tx_queue_set(void *arg)
{
    struct dpdk_virtio_tx_queue_set_params *p = arg;
    struct vr_dpdk_queue *tx_queue;
    struct dpdk_virtio_writer *port;
    struct vr_dpdk_lcore *lcore;
    struct vr_interface *vif;

    /* Check if vif is still valid */
    vif = __vrouter_get_interface(vrouter_get(0), p->vif_id);
    if (!vif || vif->vif_gen != p->vif_gen) {
        rte_free(arg);
        return;
    }

    lcore = vr_dpdk.lcores[rte_lcore_id()];
    tx_queue = &lcore->lcore_tx_queues[p->vif_id][0];
    port = (struct dpdk_virtio_writer *)tx_queue->q_queue_h;

    /* Assign new queue to the lcore's tx_queue handler */
    port->tx_virtioq = &vr_dpdk_virtio_txqs[p->vif_id][p->queue_id];

    /*
     * Each tx_queue has to have a f_flush method, but we do not need to crash
     * in other case.
     */
    if (tx_queue->txq_ops.f_flush)
        tx_queue->txq_ops.f_flush(tx_queue->q_queue_h);
    else
        RTE_LOG(ERR, VROUTER, "%s: Flush function for tx_queue(%p) unavailable\n",
                __func__, tx_queue);

    rte_free(arg);
}

struct dpdk_virtio_rx_queue_set_params {
    bool enable;
    unsigned int vif_id;
    unsigned int vif_gen;
    unsigned int queue_id;
};


void
dpdk_lcore_queue_add(unsigned lcore_id, struct vr_dpdk_q_slist *q_head,
                     struct vr_dpdk_queue *queue);
void
dpdk_lcore_rx_queue_remove(struct vr_dpdk_lcore *lcore,
                           struct vr_dpdk_queue *rx_queue,
                           bool clear_f_rx);

/*
 * Called on uvhost lcore only.
 */
void
vr_dpdk_virtio_rx_queue_enable_disable(unsigned int vif_id,
                                       unsigned int vif_gen,
                                       unsigned int queue_id,
                                       bool enable)
{
    struct dpdk_virtio_rx_queue_set_params *arg;

    /*
     * Ignore requests for queue number 0. It has already been added to lcore's
     * list of queues and can never be disabled (qemu never sends the 'disable'
     * command for queue 0). Doing otherwise would result in double adding the
     * virtio queue to lcore's list of rx queues.
     */
    if (queue_id == 0)
        return;

    arg = rte_malloc("virtio_rx_queue_set", sizeof(*arg), 0);

    arg->vif_id = vif_id;
    arg->vif_gen = vif_gen;
    arg->queue_id = queue_id;
    arg->enable = enable;

    vr_dpdk_lcore_cmd_post(VR_DPDK_NETLINK_LCORE_ID,
                           VR_DPDK_LCORE_RX_QUEUE_SET_CMD, (uint64_t)arg);
}

/*
 * Called only on netlink lcore.
 */
void
vr_dpdk_virtio_rx_queue_set(void *arg)
{
    struct dpdk_virtio_rx_queue_set_params *p = arg;
    struct vr_interface *vif;
    struct vr_dpdk_queue *rx_queue;
    struct vr_dpdk_lcore *lcore;
    unsigned int lcore_id;
    struct vr_dpdk_lcore_rx_queue_remove_arg *rx_rm_arg;

    /* Check if vif is still valid */
    vif = __vrouter_get_interface(vrouter_get(0), p->vif_id);
    if (!vif || vif->vif_gen != p->vif_gen) {
        rte_free(arg);
        return;
    }

    if (p->enable) {
        lcore_id = vif_rx_queue_lcore[p->vif_id][p->queue_id];
        lcore = vr_dpdk.lcores[lcore_id];
        rx_queue = &lcore->lcore_rx_queues[p->vif_id];
        lcore->lcore_rx_queues[p->vif_id].vring_queue_id = p->queue_id;
        dpdk_lcore_queue_add(lcore_id, &lcore->lcore_rx_head, rx_queue);

    } else {
        lcore_id = vif_rx_queue_lcore[p->vif_id][p->queue_id];
        lcore = vr_dpdk.lcores[lcore_id];
        rx_queue = &lcore->lcore_rx_queues[p->vif_id];
        if (rx_queue->enabled) {
            rx_rm_arg = rte_malloc("lcore_rx_queue_rm_cmd", sizeof(*rx_rm_arg),
                    0);
            rx_rm_arg->vif_id = vif->vif_idx;
            rx_rm_arg->clear_f_rx = false;
            rx_rm_arg->free_arg = true;
            vr_dpdk_lcore_cmd_post(lcore_id, VR_DPDK_LCORE_RX_RM_CMD,
                                   (uint64_t)rx_rm_arg);
        }
    }

    rte_free(arg);
}


#ifdef RTE_PORT_STATS_COLLECT

#define DPDK_VIRTIO_READER_STATS_PKTS_IN_ADD(port, val) \
        port->stats.n_pkts_in += val
#define DPDK_VIRTIO_READER_STATS_PKTS_DROP_ADD(port, val) \
        port->stats.n_pkts_drop += val

#else

/* keep compiler happy, for unused variables */
#define DPDK_VIRTIO_READER_STATS_PKTS_IN_ADD(port, val) \
        (void)(val)
#define DPDK_VIRTIO_READER_STATS_PKTS_DROP_ADD(port, val) \
        (void)(val)

#endif

static inline uint32_t
dpdk_virtio_get_ip_tcp_hdr_len(char *pkt_addr, uint32_t pkt_len)
{
    struct vr_eth *eth_hdr = (struct vr_eth*)pkt_addr;
    struct vr_ip6 *ipv6_hdr = NULL;
    struct vr_tcp *tcp_hdr = NULL;
    unsigned int pull_len = VR_ETHER_HLEN;
    unsigned short eth_proto;

    if (unlikely(pkt_len < pull_len))
        return 0;

    eth_proto = eth_hdr->eth_proto;

    /* Skip VLAN tag which may be present if VM sends tagged pkts */
    while (eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_VLAN)) {
        if (unlikely(pkt_len < pull_len + VR_VLAN_HLEN))
            return 0;
        eth_proto = ((struct vr_vlan_hdr *)((uintptr_t)eth_hdr + pull_len))->vlan_proto;
        pull_len += VR_VLAN_HLEN;
    }

    if (likely(eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP))) {
        struct vr_ip *ipv4_hdr = NULL;
        uint32_t ipv4_hlen;
        ipv4_hdr = (struct vr_ip *)((uintptr_t)eth_hdr + pull_len);

        if (unlikely(pkt_len < pull_len + sizeof(struct vr_ip)))
            return 0;

        ipv4_hlen = ((ipv4_hdr->ip_hl) * RTE_IPV4_IHL_MULTIPLIER);
        pull_len += ipv4_hlen;
        tcp_hdr = (struct vr_tcp*)((uint8_t*)ipv4_hdr + ipv4_hlen);
    } else if (eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP6)) {
        ipv6_hdr = (struct vr_ip6 *)((uintptr_t)eth_hdr + pull_len);

        if (unlikely(pkt_len < pull_len + sizeof(struct vr_ip6)))
            return 0;

        pull_len += sizeof(*ipv6_hdr);
        tcp_hdr = (struct vr_tcp*)((uint8_t*)ipv6_hdr + sizeof(*ipv6_hdr));
    }
    if (likely(tcp_hdr != NULL)) {
        pull_len +=  (VR_TCP_OFFSET(tcp_hdr->tcp_offset_r_flags) << 2);
    }

    return pull_len;
}

static inline char *dpdk_pktmbuf_append(struct rte_mbuf *m, struct rte_mbuf *last, uint16_t len)
{
    void *tail;
    struct rte_mbuf *m_last;

    __rte_mbuf_sanity_check(m, 1);
    __rte_mbuf_sanity_check(last, 1);

    m_last = rte_pktmbuf_lastseg(last);
    if (unlikely(len > rte_pktmbuf_tailroom(m_last)))
        return NULL;

    tail = (char *)m_last->buf_addr + m_last->data_off + m_last->data_len;
    m_last->data_len = (uint16_t)(m_last->data_len + len);
    m->pkt_len  = (m->pkt_len + len);
    return (char*) tail;
}

/*
 * dpdk_virtio_from_vm_rx - receive packets from a virtio client so that
 * the packets can be handed to vrouter for forwarding. the virtio client is
 * usually a VM.
 *
 * Returns the number of packets received from the virtio.
 */
static int
dpdk_virtio_from_vm_rx(void *port, struct rte_mbuf **pkts, uint32_t max_pkts)
{
    struct dpdk_virtio_reader *p = (struct dpdk_virtio_reader *)port;
    vr_dpdk_virtioq_t *vq = p->rx_virtioq;
    vr_uvh_client_t *vru_cl;
    uint16_t nb_pkts = 0;
    int rx_ring_queue_id;

    if (unlikely(vq->vdv_ready_state == VQ_NOT_READY)) {
        DPDK_UDEBUG(VROUTER, &vq->vdv_hash, "%s: queue %p is not ready\n",
                __func__, vq);
        return 0;
    }

    vru_cl = vr_dpdk_virtio_get_vif_client(vq->vdv_vif_idx);
    if (unlikely(vru_cl == NULL)) {
        return 0;
    }

    if (unlikely(vru_cl->vruc_state != VR_CLIENT_READY)) {
        RTE_LOG_DP(DEBUG, UVHOST, "%s: RX client is not ready, queue %p\n",
                __func__, vq);
        return 0;
    }

    if (unlikely(vru_cl->vruc_vid < 0)) {
        RTE_LOG_DP(ERR, UVHOST, "%s: RX Device not setup, queue %p\n",
                __func__, vq);
        return 0;
    }

    // rx_ring_queue_id = (0x1 << vq->vdv_queue_id) | 0x1;
    rx_ring_queue_id = 0x1;
    nb_pkts = rte_vhost_dequeue_burst(vru_cl->vruc_vid, rx_ring_queue_id, vr_dpdk.rss_mempool, pkts, (uint16_t)max_pkts);

    return nb_pkts;
}

#ifdef RTE_PORT_STATS_COLLECT

#define DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(port, val) \
        port->stats.n_pkts_in += val
#define DPDK_VIRTIO_WRITER_STATS_PKTS_DROP_ADD(port, val) \
        port->stats.n_pkts_drop += val

#else

/* keep compiler happy, for unused variables */
#define DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(port, val) \
        (void)(val)
#define DPDK_VIRTIO_WRITER_STATS_PKTS_DROP_ADD(port, val) \
        (void)(val)

#endif

/*
 * dpdk_virtio_to_vm_tx - sends a packet from vrouter to a virtio client. The
 * virtio client is usually a VM.
 *
 * Returns nothing.
 */
static int
dpdk_virtio_to_vm_tx(void *port, struct rte_mbuf *pkt)
{
    struct dpdk_virtio_writer *p = (struct dpdk_virtio_writer *)port;
    vr_dpdk_virtioq_t *vq = p->tx_virtioq;
    uint16_t nb_pkts = 0;
    int tx_ring_queue_id;
    vr_uvh_client_t *vru_cl;

    vru_cl = vr_dpdk_virtio_get_vif_client(vq->vdv_vif_idx);
    if (unlikely(vru_cl == NULL)) {
        RTE_LOG_DP(ERR, UVHOST, "%s: TX client not found, queue %p\n",
                __func__, vq);
        return 0;
    }

    if (unlikely(vq->vdv_ready_state == VQ_NOT_READY))
        return 0;

    if (unlikely(vru_cl->vruc_vid < 0)) {
        RTE_LOG_DP(ERR, UVHOST, "%s: TX Device not setup, queue %p\n",
                __func__, vq);
        return 0;
    }
    
    // tx_ring_queue_id = (0x1 << vq->vdv_queue_id);
    tx_ring_queue_id = 0x0;
    nb_pkts = rte_vhost_enqueue_burst(vru_cl->vruc_vid, tx_ring_queue_id, &pkt, 1);
    if (!nb_pkts) {
        // error
        RTE_LOG_DP(ERR, UVHOST, "%s: TX Unable to send Pkt, queue %p\n",
                __func__, vq);
    }

    DPDK_VIRTIO_WRITER_STATS_PKTS_IN_ADD(p, 1);
    /* rte_vhost_enqueue_burst does not free any mbufs */
    rte_pktmbuf_free(pkt);

    return 0;
}

/*
 * dpdk_virtio_to_vm_flush - flushes packets from vrouter to a virtio client.
 * The virtio client is usually a VM.
 *
 * Returns nothing.
 */
#if 1
// NAREN TBD VM shutdown
static int
dpdk_virtio_to_vm_flush(void *port  __attribute__((unused)))
{
    return 0;
}
#endif    

#if 0
NAREN NAREN naren check, this function is called during qemu shutdown
and rte_wmb() and synchronize_rcu() getting called

/*
 * vr_dpdk_virtio_get_vring_base - gets the vring base for the specified vring
 * sent by the vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_virtio_get_vring_base(unsigned int vif_idx, unsigned int vring_idx,
                               unsigned int *vring_basep)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    *vring_basep = vq->vdv_last_used_idx;

    /*
     * This is usually called when qemu shuts down a virtio queue. Set the
     * state to indicate that this queue should not be used any more.
     */
    vq->vdv_ready_state = VQ_NOT_READY;
    rte_wmb();
    synchronize_rcu();

    /* Reset the queue. We reset only those values we analyze in
     * uvhm_check_vring_ready()
     */
    vq->vdv_desc = NULL;
    if (vq->vdv_callfd) {
        close(vq->vdv_callfd);
        vq->vdv_callfd = 0;
    }

    return 0;
}

/*
 * vr_dpdk_set_vring_addr - Sets the address of the virtio descriptor and
 * available/used rings based on messages sent by the vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_set_vring_addr(unsigned int vif_idx, unsigned int vring_idx,
                       struct vring_desc *vrucv_desc,
                       struct vring_avail *vrucv_avail,
                       struct vring_used *vrucv_used)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_desc = vrucv_desc;
    vq->vdv_avail = vrucv_avail;
    vq->vdv_used = vrucv_used;

    /*
     * Tell the guest that it need not interrupt vrouter when it updates the
     * available ring (as vrouter is polling it).
     */
    vq->vdv_used->flags |= VRING_USED_F_NO_NOTIFY;

    return 0;
}

/*
 * vr_dpdk_set_ring_num_desc - sets the number of descriptors in a vring
 * based on messages from the vhost client.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_set_ring_num_desc(unsigned int vif_idx, unsigned int vring_idx,
                          unsigned int num_desc)
{
    vr_dpdk_virtioq_t *vq;

    if ((vif_idx >= VR_MAX_INTERFACES) || (vring_idx > 2 * VR_DPDK_VIRTIO_MAX_QUEUES)) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

    vq->vdv_size = num_desc;

    return 0;
}
#endif

/*
 * vr_dpdk_set_virtq_ready - sets the virtio queue ready state to indicate
 * whether forwarding can start on the virtio queue or not.
 *
 * Returns 0 on success, -1 otherwise.
 */
int
vr_dpdk_set_virtq_ready(unsigned int vif_idx, unsigned int vring_idx,
                        vq_ready_state_t ready)
{
    vr_dpdk_virtioq_t *vq;

        RTE_LOG_DP(DEBUG, UVHOST, "vif idx %d setting ready state\n", vif_idx);
    if ((vif_idx >= VR_MAX_INTERFACES)
        || (vring_idx >= (2 * VR_DPDK_VIRTIO_MAX_QUEUES))) {
        return -1;
    }

    /*
     * RX rings are even numbered and TX rings are odd numbered from the
     * VM's point of view. From vrouter's point of view, VM's TX ring is
     * vrouter's RX ring and vice versa.
     */
    if (vring_idx & 1) {
        vq = &vr_dpdk_virtio_rxqs[vif_idx][vring_idx/2];
    } else {
        vq = &vr_dpdk_virtio_txqs[vif_idx][vring_idx/2];
    }

        RTE_LOG_DP(DEBUG, UVHOST, "NAREN setting ready state\n");
    vq->vdv_ready_state = ready;
        RTE_LOG_DP(DEBUG, UVHOST, "NAREN Done setting ready state\n");

    return 0;
}

/*
 * vr_dpdk_virtio_set_vif_client - sets a pointer to per vif state. Currently
 * used to store a pointer to the vhost client structure.
 *
 * Returns nothing.
 */
void
vr_dpdk_virtio_set_vif_client(unsigned int idx, void *client)
{
    if (idx >= VR_MAX_INTERFACES) {
        return;
    }

    vr_dpdk_vif_clients[idx] = client;

    return;
}

/*
 * vr_dpdk_virtio_get_vif_client - returns a pointer to per vif state if it
 * exists, NULL otherwise.
 */
void *
vr_dpdk_virtio_get_vif_client(unsigned int idx)
{
    if (idx >= VR_MAX_INTERFACES) {
        return NULL;
    }

    return vr_dpdk_vif_clients[idx];
}

static int
dpdk_virtio_writer_stats_read(void *port,
    struct rte_port_out_stats *stats, int clear)
{
    struct dpdk_virtio_reader *p = (struct dpdk_virtio_reader *)port;

    if (stats != NULL)
        memcpy(stats, &p->stats, sizeof(p->stats));

    if (clear)
        memset(&p->stats, 0, sizeof(p->stats));

    return 0;
}

/* Update extra statistics for virtio queue */
void
vr_dpdk_virtio_xstats_update(struct vr_interface_stats *stats,
    struct vr_dpdk_queue *queue)
{
    struct dpdk_virtio_reader *reader;
    struct dpdk_virtio_writer *writer;

    if (queue->rxq_ops.f_rx == vr_dpdk_virtio_reader_ops.f_rx) {
        reader = (struct dpdk_virtio_reader *)queue->q_queue_h;
        stats->vis_port_isyscalls = reader->nb_syscalls;
        stats->vis_port_inombufs = reader->nb_nombufs;
    } else if (queue->txq_ops.f_tx == vr_dpdk_virtio_writer_ops.f_tx) {
        writer = (struct dpdk_virtio_writer *)queue->q_queue_h;
        stats->vis_port_osyscalls = writer->nb_syscalls;
    }
}
