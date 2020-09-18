/*
 * vr_dpdk_info.c - DPDK specific callback functions for vr_info .
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

    ret = vr_dpdk_ddp_add((uint16_t)DDP_GET_PORT_ID());
    if(ret != 0) {
        VI_PRINTF("Programming DDP image mplsogreudp -  failed(%d) \n\n", ret);
    } else {
        vr_dpdk_set_ddp();
        VI_PRINTF("Programming DDP image mplsogreudp - success \n\n");
    }
    return 0;
}


int
dpdk_conf_del_ddp(VR_INFO_ARGS)
{
    VR_INFO_BUF_INIT();
    int ret;

    ret = vr_dpdk_ddp_del((uint16_t)DDP_GET_PORT_ID());
    if(ret != 0) {
        VI_PRINTF("Removing DDP image mplsogreudp -  failed(%d) \n\n", ret);
    } else {
        vr_dpdk_reset_ddp();
        VI_PRINTF("Removing DDP image mplsogreudp - success \n\n");
    }
    return 0;
}
