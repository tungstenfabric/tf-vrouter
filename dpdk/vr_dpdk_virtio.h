/*
 * vr_dpdk_virtio.h - header for DPDK virtio forwarding infrastructure.
 *
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DPDK_VIRTIO_H__
#define __VR_DPDK_VIRTIO_H__

/*
 * Burst size for packets from a VM
 */
#define VR_DPDK_VIRTIO_RX_BURST_SZ VR_DPDK_RX_BURST_SZ
/*
 * Burst size for packets to a VM
 */
#define VR_DPDK_VIRTIO_TX_BURST_SZ VR_DPDK_TX_BURST_SZ
/*
 * Maximum number of queues per virtio device
 */
#define VR_DPDK_VIRTIO_MAX_QUEUES 16

#define VR_BUF_VECTOR_MAX 256


typedef enum vq_ready_state {
    VQ_NOT_READY,
    VQ_READY,
} vq_ready_state_t;

struct dpdk_virtio_writer;

/* virtio queue */
typedef struct vr_dpdk_virtioq {
    uint16_t            vdv_ready_state;
    uint16_t            vdv_vif_idx;
    int                 vdv_vid; /* vhost device id */
    int                 vdv_queue_id; /* queue_id */
    DPDK_DEBUG_VAR(uint32_t vdv_hash);
} __rte_cache_aligned vr_dpdk_virtioq_t;

uint16_t vr_dpdk_virtio_nrxqs(struct vr_interface *vif);
uint16_t vr_dpdk_virtio_ntxqs(struct vr_interface *vif);

struct vr_dpdk_queue *
vr_dpdk_virtio_rx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int queue_id);
struct vr_dpdk_queue *
vr_dpdk_virtio_tx_queue_init(unsigned int lcore_id, struct vr_interface *vif,
                             unsigned int queue_id);

void
vr_dpdk_virtio_tx_queue_enable_disable(unsigned int vif_id,
                                       unsigned int vif_gen,
                                       unsigned int queue_id,
                                       bool enable);
void
vr_dpdk_virtio_rx_queue_enable_disable(unsigned int vif_id,
                                       unsigned int vif_gen,
                                       unsigned int queue_id,
                                       bool enable);
// naren need changes in this func
void
vr_dpdk_virtio_tx_queue_set(void *arg);
void
// naren need changes in this func
vr_dpdk_virtio_rx_queue_set(void *arg);

int vr_dpdk_set_virtq_ready(unsigned int vif_idx, unsigned int vring_idx, vq_ready_state_t ready);
void vr_dpdk_virtio_set_vif_client(unsigned int idx, void *client);
void *vr_dpdk_virtio_get_vif_client(unsigned int idx);
// NAREN TBD VM shutdown
// int vr_dpdk_virtio_stop(unsigned int vif_idx);

void vr_dpdk_virtio_xstats_update(struct vr_interface_stats *stats,
    struct vr_dpdk_queue *queue);

extern struct rte_port_in_ops vr_dpdk_virtio_reader_ops;
extern struct rte_port_out_ops vr_dpdk_virtio_writer_ops;

extern struct vr_dpdk_virtioq vr_dpdk_virtio_rxqs[VR_MAX_INTERFACES][VR_DPDK_VIRTIO_MAX_QUEUES];
extern struct vr_dpdk_virtioq vr_dpdk_virtio_txqs[VR_MAX_INTERFACES][VR_DPDK_VIRTIO_MAX_QUEUES];
#endif /* __VR_DPDK_VIRTIO_H__ */
