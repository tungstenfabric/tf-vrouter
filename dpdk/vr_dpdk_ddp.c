/*
 * vr_dpdk_ddp.c - DDP specific API's for adding/deleting the firmware.
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "vr_dpdk.h"

#include <rte_eth_bond.h>
#include <rte_pmd_i40e.h>
#include <rte_errno.h>

/* By default, enable DDP for X710 series NIC's */
static bool vr_dpdk_enable_ddp = true;

bool
vr_dpdk_get_ddp(void)
{
    return vr_dpdk_enable_ddp;
}

void
vr_dpdk_set_ddp(void)
{
    vr_dpdk_enable_ddp = true;
}

void
vr_dpdk_reset_ddp(void)
{
    vr_dpdk_enable_ddp = false;
}

int
vr_dpdk_ddp_get_portid(void)
{
    int i;
    struct vr_dpdk_ethdev *ethdev;
    struct rte_eth_dev *dev;
    uint16_t slave_port_id, port_id = vr_dpdk_master_port_id;

    if(rte_eth_dev_is_valid_port(port_id)) {
         ethdev = &vr_dpdk.ethdevs[port_id];

    if (ethdev->ethdev_nb_slaves > 0) {
        for (i = 0; i < ethdev->ethdev_nb_slaves; i++) {
            slave_port_id = ethdev->ethdev_slaves[i];
            dev = &rte_eth_devices[slave_port_id];
            if(!strcmp(dev->device->driver->name, "net_i40e")) {
                 return slave_port_id;
            }
        }
    } else {
            dev = &rte_eth_devices[ethdev->ethdev_port_id];
            if(!strcmp(dev->device->driver->name, "net_i40e")) {
                return ethdev->ethdev_port_id;
            }
        }
    }
    return -1;
}

int
vr_dpdk_ddp_add(uint16_t port_id)
{
    int ddp_fd, ret = -ENOTSUP;
    uint8_t *buf;
    struct stat st_buf;
    char ddp_fpath[] = "/usr/bin/mplsogreudp.pkg";

    if(!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, VROUTER, "%s : DDP port_id is invalid \n", __func__);
        return -1;
    }

    ddp_fd = open(ddp_fpath, O_RDONLY);
    if(ddp_fd == -1) {
        RTE_LOG(ERR, VROUTER, "%s: Failed to open mplsogreudp.pkg file \n",
                    __func__);
        return -1;
    }
    if ((fstat(ddp_fd, &st_buf) != 0) || (!S_ISREG(st_buf.st_mode))) {
        close(ddp_fd);
        RTE_LOG(ERR, VROUTER, "%s: File operation failed for mplsogreudp.pkg\n",
                    __func__);
        return -1;
    }

    if(st_buf.st_size < 0) {
        close(ddp_fd);
        RTE_LOG(ERR, VROUTER, "%s: File operation failed for mplsogreudp.pkg"
                "while reading size %ld \n", __func__, st_buf.st_size);
        return -1;
    }

    buf = (uint8_t *)vr_zalloc(st_buf.st_size, VR_INFO_REQ_OBJECT);
    if(!buf) {
        close(ddp_fd);
        RTE_LOG(ERR, VROUTER, "%s: Memory allocation failed for size %ld\n",
                    __func__, st_buf.st_size);
        return -1;
    }

    ret = read(ddp_fd, buf, st_buf.st_size);
    if(ret < 0) {
        close(ddp_fd);
        vr_free(buf, VR_INFO_REQ_OBJECT);
        RTE_LOG(ERR, VROUTER, "%s: File read operation failed for"
                    "mplsogreudp.pkg\n", __func__);
        return -1;
    }

    ret = rte_pmd_i40e_process_ddp_package(port_id, buf, st_buf.st_size,
            RTE_PMD_I40E_PKG_OP_WR_ADD);

    if(ret == -ENOTSUP) {
        RTE_LOG(ERR, VROUTER, "%s: DDP works only on X710 NIC series \n\n",
                    __func__);
    } else if(ret < 0) {
        RTE_LOG(ERR, VROUTER, "%s: Failed to load profile return value is %d\n",
                    __func__, ret);
    } else {
        RTE_LOG(INFO, VROUTER, "%s DDP programming was successful\n",
                    __func__);
    }

    if (ddp_fd) {
        close(ddp_fd);
    }

    if (buf) {
        vr_free(buf, VR_INFO_REQ_OBJECT);
    }

    return ret;
}

int
vr_dpdk_ddp_del(uint16_t port_id)
{
    int ddp_fd, ret = -ENOTSUP;
    uint8_t *buf;
    struct stat st_buf;

    char ddp_fpath[] = "/usr/bin/mplsogreudp.pkg";

    if(!rte_eth_dev_is_valid_port(port_id)) {
        RTE_LOG(ERR, VROUTER, "%s: DDP port_id is invalid \n", __func__);
        return -1;
    }

    ddp_fd = open(ddp_fpath, O_RDONLY);
    if(ddp_fd == -1) {
        RTE_LOG(ERR, VROUTER, "%s: Failed to open mplsogre.bkp file\n",
                    __func__);
        return -1;
    }

    if ((fstat(ddp_fd, &st_buf) != 0) || (!S_ISREG(st_buf.st_mode))) {
        close(ddp_fd);
        RTE_LOG(ERR, VROUTER, "%s: File operation failed for mplsogre.bkp\n",
                    __func__);
        return -1;
    }

    if(st_buf.st_size < 0) {
        close(ddp_fd);
        RTE_LOG(ERR, VROUTER, "%s: File operation failed for mplsogre.pkg"
                "while reading size %ld \n", __func__, st_buf.st_size);
        return -1;
    }

    buf = (uint8_t *)vr_zalloc(st_buf.st_size, VR_INFO_REQ_OBJECT);
    if(!buf) {
        close(ddp_fd);
        RTE_LOG(ERR, VROUTER, "%s: Memory allocation failed if size %ld\n",
                    __func__, st_buf.st_size);
        return -1;
    }

    ret = read(ddp_fd, buf, st_buf.st_size);
    if(ret < 0) {
        close(ddp_fd);
        vr_free(buf, VR_INFO_REQ_OBJECT);
        RTE_LOG(ERR, VROUTER, "%s: File read operation failed for"
                    "mplsogreudp.bkp\n", __func__);
        return -1;
    }

    ret = rte_pmd_i40e_process_ddp_package(port_id, buf, st_buf.st_size,
            RTE_PMD_I40E_PKG_OP_WR_DEL);
    if(ret == -ENOTSUP) {
        RTE_LOG(ERR, VROUTER, "%s: DDP works only on X710 NIC series\n",
                    __func__);
    } else if(ret < 0) {
        RTE_LOG(ERR, VROUTER, "%s: Failed to delete profile return value is %d\n",
                    __func__, ret);
    } else {
        RTE_LOG(INFO, VROUTER, "%s: Removed DDP image mplsogreudp - success\n",
                    __func__);
    }

    if(ddp_fd) {
        close(ddp_fd);
    }

    if(buf) {
        vr_free(buf, VR_INFO_REQ_OBJECT);
    }

    return ret;
}

