/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_representor_impl.h"

#include <rte_eth_bond.h>
#include <rte_port_ethdev.h>
#include <rte_spinlock.h>

rte_spinlock_t agent_socket_lock;

static int
send_port_info_to_agent(uint16_t port_id, uint8_t vif_idx)
{
    int ret;
    char *str[] = {"UP", "DOWN"};
    struct rte_eth_link link;
    unsigned bond_type;
    uint32_t dev_flags;
    struct vr_dpdk_bond_member_info member_info;

    memset(&member_info, 0, sizeof(member_info));

    rte_eth_link_get_nowait(port_id, &link);
    member_info.status = link.link_status;

    ret = rte_eth_dev_get_name_by_port(port_id, member_info.intf_name);
    if(ret != 0) {
        RTE_LOG(ERR, VROUTER, "%s(): rte_eth_dev_get_name_by_port failed\n", __func__);
        return ret;
    }

    if(rte_eth_devices[port_id].device->driver->name == NULL) {
        RTE_LOG(ERR, VROUTER, "%s(): failed - bad EAL configuration?\n", __func__);
        return -EINVAL;
    }

    snprintf(member_info.intf_drv_name, (VR_INTERFACE_NAME_LEN - 1),
        "%s", rte_eth_devices[port_id].device->driver->name);

    RTE_LOG(INFO, VROUTER, "%s(): Port ID: %d Link Status: %s intf_name:%s \
            drv_name:%s \n\n", __func__, port_id, (link.link_status?str[0]:str[1]),
            member_info.intf_name, member_info.intf_drv_name);

    dev_flags = rte_eth_devices[port_id].data->dev_flags;

    //not bonded representors are marked as bond masters by vRouter
    bond_type = (dev_flags & RTE_ETH_DEV_BONDED_SLAVE) ? VR_DPDK_BOND_SLAVE :
        VR_DPDK_BOND_MASTER;

    rte_spinlock_lock(&agent_socket_lock);

    vr_dpdk_nl_send_bond_intf_state(&member_info, bond_type, vif_idx);

    rte_spinlock_unlock(&agent_socket_lock);

    return 0;
}

static int
n3k_link_change_handler(uint16_t port_id, enum rte_eth_event_type type,
        void *param, void *ret_param __rte_unused)
{
    struct vr_dpdk_ethdev *ethdev = (struct vr_dpdk_ethdev *)param;

    RTE_LOG(DEBUG, VROUTER, "%s(): called\n", __func__);

    if(ethdev == NULL) {
        RTE_LOG(ERR, VROUTER, "%s: ethdev is null\n", __func__);
        return -1;
    }

    rte_spinlock_lock(&ethdev->ethdev_lock);

    /* Force master notification */
    if(ethdev->ethdev_port_id != port_id)
        send_port_info_to_agent(ethdev->ethdev_port_id, ethdev->ethdev_vif_idx);

    rte_spinlock_unlock(&ethdev->ethdev_lock);

    RTE_LOG(DEBUG, VROUTER, "%s(): sending link info to agent\n", __func__);
    return send_port_info_to_agent(port_id, ethdev->ethdev_vif_idx);
}

void
vr_dpdk_n3k_link_intr_setup(struct vr_dpdk_ethdev *ethdev)
{
    int i = 0, ret = 0;
    uint8_t port_id = ethdev->ethdev_port_id;

    RTE_LOG(DEBUG, VROUTER, "%s(): start\n", __func__);

    ret = rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC,
        n3k_link_change_handler, ethdev);

    if (ret)
        RTE_LOG(WARNING, VROUTER, "%s(): rte_eth_dev_callback_register failed for %d\n",
            __func__, port_id);

    send_port_info_to_agent(port_id, ethdev->ethdev_vif_idx);

    /* assumption that ethdev_nb_slaves is only higher than 0 for bonding */
    for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
        port_id = ethdev->ethdev_slaves[i];

        /* register our representors */
        ret = rte_eth_dev_callback_register(port_id, RTE_ETH_EVENT_INTR_LSC,
            n3k_link_change_handler, ethdev);
        if(ret)
            RTE_LOG(ERR, VROUTER, "%s(): rte_eth_dev_callback_register failed for %d\n",
                __func__, port_id);

        send_port_info_to_agent(port_id, ethdev->ethdev_vif_idx);
    }

    RTE_LOG(DEBUG, VROUTER, "%s(): end\n", __func__);
}

void
vr_dpdk_n3k_link_init(void)
{
    rte_spinlock_init(&agent_socket_lock);
}

void
vr_dpdk_n3k_link_exit(void)
{
    return;
}
