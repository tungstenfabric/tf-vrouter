/*
 * vr_dpdk_conf.c - DPDK specific callback functions for dpdkconf CLI.
 *
 * Copyright (c) 2020 Juniper Networks, Inc. All rights reserved.
 */

#include <vr_os.h>
#include <vr_types.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "vr_dpdk.h"
#include "vrouter.h"

int
dpdk_conf_add_ddp(VR_INFO_ARGS)
{
    VR_INFO_BUF_INIT();
    int ret;

    ret = vr_dpdk_process_ddp_package(VR_DPDK_DDP_ADD);
    if(ret == 0) {
        vr_dpdk_set_ddp();
        VI_PRINTF("Programming DDP image mplsogreudp - success \n\n");
        return 0;
    } else if (ret == VR_DPDK_DDP_FAILED) {
        VI_PRINTF("Failed to load DDP profile, Check DPDK log file for errors\n\n");
    } else if(ret == VR_DPDK_DDP_NOT_SUPPORTED) {
        VI_PRINTF("DDP works only on X710 NIC series\n\n");
    } else {
        VI_PRINTF("Programming DDP image mplsogreudp -  failed(%d) \n\n", ret);
    }
    /* If DDP firmware not programmed on any ports, then dont disable software
     * load balancing */
    vr_dpdk_reset_ddp();
    return 0;
}

int
dpdk_conf_del_ddp(VR_INFO_ARGS)
{
    VR_INFO_BUF_INIT();
    int ret;

    ret = vr_dpdk_process_ddp_package(VR_DPDK_DDP_DELETE);
    if(ret == 0) {
        vr_dpdk_reset_ddp();
        VI_PRINTF("Removing DDP image mplsogreudp - success \n\n");
    } else if (ret == VR_DPDK_DDP_FAILED) {
        VI_PRINTF("Failed to remove DDP profile, Check DPDK log file for errors\n\n");
    } else if(ret == VR_DPDK_DDP_NOT_SUPPORTED) {
        VI_PRINTF("DDP works only on X710 NIC series\n\n");
    } else {
        VI_PRINTF("Removing DDP image mplsogreudp -  failed(%d) \n\n", ret);
    }
    return 0;
}
