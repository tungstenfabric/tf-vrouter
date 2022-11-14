/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_representor_impl.h"

#include <rte_eth_bond.h>
#include <rte_eth_bond_8023ad.h>
#include <rte_port_ethdev.h>
#include <rte_errno.h>

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

#define N3K_REPRESENTOR_QUEUE_COUNT 1
#define BONDED_REPRESENTOR_MAX_COUNT 2

static bool
is_bonding_representor(uint16_t port_id)
{
    if (rte_eth_devices[port_id].device->driver != NULL &&
       (strcmp(rte_eth_devices[port_id].device->driver->name, "net_bonding") == 0)) {
        return true;
    }

    return false;
}

static void
n3k_representor_show_info(struct vr_interface *vif, struct vr_dpdk_ethdev *ethdev,
                      const char *repr_name, uint16_t port_id)
{
    struct rte_ether_addr mac_addr;
    struct rte_eth_dev_info dev_info;
    char tmpLogBuff[RTE_DEV_NAME_MAX_LEN];

    RTE_LOG(INFO, VROUTER,
        "%s(): VIF eth dev %s with MAC " MAC_FORMAT "\n",
        __func__, vif->vif_name, MAC_VALUE(vif->vif_mac));

    rte_eth_macaddr_get(port_id, &mac_addr);
    rte_ether_format_addr(tmpLogBuff, RTE_DEV_NAME_MAX_LEN, &mac_addr);
    RTE_LOG(INFO, VROUTER, "%s(): representor <%s> with MAC <%s>\n",
        __func__, repr_name, tmpLogBuff);

    rte_eth_dev_info_get(ethdev->ethdev_port_id, &dev_info);

    RTE_LOG(DEBUG, VROUTER, "%s(%s): dev_info: driver_name=%s"
        " max_rx_queues=%" PRIu16 " max_tx_queues=%" PRIu16
        " rx_offload_capa=%" PRIx64 " tx_offload_capa=%" PRIx64 "\n",
        __func__, vif->vif_name, dev_info.driver_name,
        dev_info.max_rx_queues, dev_info.max_tx_queues,
        dev_info.rx_offload_capa, dev_info.tx_offload_capa);
}

static void
bond_info_update(struct vr_dpdk_ethdev *ethdev, const char *repr_name)
{
    int i, slave_port_id;
    int port_id = ethdev->ethdev_port_id;
    uint16_t mtu = 0;
    char slave_name[VR_INTERFACE_NAME_LEN] = "";

    ethdev->ethdev_nb_slaves = rte_eth_bond_slaves_get(port_id,
        ethdev->ethdev_slaves, BONDED_REPRESENTOR_MAX_COUNT);

    for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
        slave_port_id = ethdev->ethdev_slaves[i];

        if (rte_eth_dev_get_name_by_port(slave_port_id, slave_name)) {
            RTE_LOG(ERR, VROUTER, "%s(): %s: unexpected missing name of slave device\n",
                __func__, repr_name);
            return;
        }

        if (!rte_eth_devices[port_id].data->mtu) {
            rte_eth_dev_get_mtu(slave_port_id, &mtu);

            RTE_LOG(DEBUG, VROUTER, "%s(): %s: setting mtu %" PRIu16" from %s\n",
                __func__, repr_name, mtu, slave_name);
            rte_eth_devices[port_id].data->mtu = mtu;
        }


        RTE_LOG(INFO, VROUTER, "%s(): %s: bond member %s found\n",
            __func__, repr_name, slave_name);
    }
}

static void
n3k_lacp_disable_dedicated_queue(struct vr_interface *vif)
{
    struct vr_dpdk_ethdev *ethdev;
    uint16_t rep_port_id;
    int __rte_unused ret;
    uint16_t slaves[RTE_MAX_ETHPORTS];
    int slaves_cnt;
    int i;

    if (vif->vif_os == NULL)
        return;

    ethdev = vif->vif_os;
    rep_port_id = ethdev->ethdev_port_id;

    if (rte_eth_bond_mode_get(rep_port_id) != BONDING_MODE_8023AD)
        return;

    rte_eth_dev_stop(rep_port_id);

    ret = rte_eth_bond_8023ad_dedicated_queues_disable(rep_port_id);
    RTE_ASSERT(ret == 0);

    slaves_cnt = rte_eth_bond_slaves_get(rep_port_id, slaves, RTE_MAX_ETHPORTS);

    for (i = 0; i < slaves_cnt; ++i) {
        ret = rte_pmd_n3k_disable_dedicated_queue_on_repr(&rte_eth_devices[slaves[i]]);
        RTE_ASSERT(ret == 0);
    }
}

static int
n3k_lacp_enable_dedicated_queue(struct vr_interface *vif, uint16_t port_id)
{
    uint16_t slaves[RTE_MAX_ETHPORTS];
    int i, slaves_cnt, ret;

    ret = rte_eth_bond_mode_get(port_id) == BONDING_MODE_8023AD ? 0 : -EINVAL;
    if (ret)
        goto err;

    slaves_cnt = rte_eth_bond_slaves_get(port_id, slaves, RTE_MAX_ETHPORTS);
    for (i = 0; i < slaves_cnt; ++i) {
        ret = rte_pmd_n3k_enable_dedicated_queue_on_repr(
            &rte_eth_devices[slaves[i]]);
        if (ret)
            goto err;
    }

    ret = rte_eth_bond_8023ad_dedicated_queues_enable(port_id);
    if (ret)
        goto err;

    RTE_LOG(INFO, VROUTER,
        "%s(): %s: Enabled dedicated LACP queue\n",
        __func__, vif->vif_name);

    return 0;

err:
    RTE_LOG(ERR, VROUTER,
        "%s(): %s: Failed to enable dedicated queue; ret: %s\n",
        __func__, vif->vif_name, rte_strerror(-ret));

    return ret;
}

static void
n3k_ethdev_config_update(struct rte_eth_conf *ethdev_conf, bool is_fabric)
{
    if (is_fabric) {
        ethdev_conf->intr_conf.lsc = 1;
    }
}

static void
n3k_ethdev_info_update(struct vr_interface *vif, struct vr_dpdk_ethdev *ethdev,
                       const char *repr_name, uint16_t port_id)
{
    ethdev->ethdev_port_id = port_id;
    ethdev->ethdev_vif_idx = vif->vif_idx;
    ethdev->ethdev_nb_rx_queues = N3K_REPRESENTOR_QUEUE_COUNT;
    ethdev->ethdev_nb_tx_queues = N3K_REPRESENTOR_QUEUE_COUNT;
    ethdev->ethdev_nb_rss_queues = N3K_REPRESENTOR_QUEUE_COUNT;
    ethdev->ethdev_reta_size = 0;

    RTE_LOG(INFO, VROUTER, "%s(): %s: tx_q_nb: %" PRIu16" rx_q_nb: %" PRIu16"\n",
        __func__, repr_name, ethdev->ethdev_nb_tx_queues, ethdev->ethdev_nb_rx_queues);
}

int
vr_dpdk_n3k_representor_ethdev_init(struct vr_interface *vif,
                            const char *repr_name,
                            uint16_t port_id)
{
    struct rte_eth_conf ethdev_conf = n3k_representor_ethdev_conf;
    struct vr_dpdk_ethdev *ethdev = &vr_dpdk.ethdevs[port_id];
    int ret;

    if (ethdev->ethdev_ptr != NULL) {
        RTE_LOG(ERR, VROUTER,
                "%s(): %s: with port id %"PRIu8" already added\n",
                __func__, repr_name, port_id);
        return -EINVAL;
    }

    ethdev->ethdev_ptr = &rte_eth_devices[port_id];

    n3k_representor_show_info(vif, ethdev, repr_name, port_id);

    n3k_ethdev_config_update(&ethdev_conf, vif_is_fabric(vif));

    n3k_ethdev_info_update(vif, ethdev, repr_name, port_id);

    rte_eth_promiscuous_enable(port_id);
    rte_eth_allmulticast_enable(port_id);

    ret = rte_eth_dev_configure(port_id,
        N3K_REPRESENTOR_QUEUE_COUNT,
        N3K_REPRESENTOR_QUEUE_COUNT,
        &n3k_representor_ethdev_conf);
    if (ret < 0) {
        RTE_LOG(ERR, VROUTER, "%s(): %s: configure failed: %s (%d)\n",
            __func__, repr_name, rte_strerror(-ret), -ret);
        return ret;
    }

    if (is_bonding_representor(port_id))
        bond_info_update(ethdev, repr_name);

    ret = vr_dpdk_n3k_representor_queue_setup(ethdev);
    if (ret) {
        RTE_LOG(ERR, VROUTER,
            "%s(): %s: queue setup failed: %s (%d)s\n",
            __func__, repr_name, rte_strerror(-ret), -ret);
        return ret;
    }

    if (rte_eth_bond_mode_get(port_id) == BONDING_MODE_8023AD) {
        ret = n3k_lacp_enable_dedicated_queue(vif, port_id);
        if (ret) {
            RTE_LOG(ERR, VROUTER,
                "%s(): %s: error while enabling lacp: %s (%d)s\n\n",
                __func__, repr_name, rte_strerror(-ret), -ret);
        }
        return ret;
    }

    rte_spinlock_init(&ethdev->ethdev_lock);

    if (vif_is_fabric(vif))
        vr_dpdk_n3k_link_intr_setup(ethdev);

    return 0;
}

int
vr_dpdk_n3k_representor_ethdev_release(struct vr_interface *vif)
{
    uint16_t port_id;
    struct vr_dpdk_ethdev *ethdev;

    ethdev = (struct vr_dpdk_ethdev *)(vif->vif_os);
    port_id = ethdev->ethdev_port_id;

    if (rte_eth_bond_mode_get(port_id) == BONDING_MODE_8023AD) {
        n3k_lacp_disable_dedicated_queue(vif);
    }

    rte_eth_dev_stop(port_id);

    return vr_dpdk_ethdev_release(ethdev);
}
