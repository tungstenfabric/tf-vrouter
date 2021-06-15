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
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <rte_log.h>
#include <rte_eal.h>

#include "vr_dpdk.h"
#include "vrouter.h"

struct rte_log_dynamic_type {
    const char *name;
    uint32_t loglevel;
};

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

int
dpdk_conf_log(VR_INFO_ARGS)
{
    VR_INFO_BUF_INIT();
    char *log_type = strtok(msg_req->inbuf," ");
    char *log_level = strtok(NULL," ");

    if (strcmp(log_type,"GLOBAL") == 0 || strcmp(log_type,"global") == 0 || strcmp(log_type,"Global") == 0) {
        VI_PRINTF("\nSetting global Loglevel to :%s ", log_level);
        VI_PRINTF("\n\n");
        rte_log_set_global_level((uint32_t) atoi(log_level));
        return 0;
    }
    if (atoi(log_level) > RTE_LOG_DEBUG || atoi(log_level) < RTE_LOG_EMERG)
        return -1;
    if (atoi(log_type) == rte_log_register("pmd.net.i40e.driver")) {
        int i40e_logtype_driver;
        i40e_logtype_driver = rte_log_register("pmd.net.i40e.driver");
        if (i40e_logtype_driver >= 0)
            rte_log_set_level(i40e_logtype_driver, atoi(log_level));
    } else if (atoi(log_type) == rte_log_register("pmd.net.bond")) {
        int bond_logtype;
        bond_logtype = rte_log_register("pmd.net.bond");
        if (bond_logtype >= 0)
            rte_log_set_level(bond_logtype, atoi(log_level));
    } else if (atoi(log_type) == rte_log_register("pmd.net.ixgbe.driver")) {
        int ixgbe_logtype_driver;
        ixgbe_logtype_driver = rte_log_register("pmd.net.ixgbe.driver");
        if (ixgbe_logtype_driver >= 0)
            rte_log_set_level(ixgbe_logtype_driver, atoi(log_level));
    } else if (atoi(log_type) == rte_log_register("pmd.net.e1000.driver")) {
        int e1000_logtype_driver;
        e1000_logtype_driver = rte_log_register("pmd.net.e1000.driver");
        if (e1000_logtype_driver >= 0)
            rte_log_set_level(e1000_logtype_driver, atoi(log_level));
    } else {
        rte_log_set_level(atoi(log_type), atoi(log_level));
    }
    if (rte_log_get_global_level() < atoi(log_level)) {
        rte_log_set_global_level((uint32_t) atoi(log_level));
    }

    VI_PRINTF("\nLog level changed for %s,current level is %s\n\n", log_type, log_level); 
    return 0;
}

static const char *
loglevel_to_string(uint32_t level)
{
    switch (level) {
    case 0: return "disabled";
    case RTE_LOG_EMERG: return "emerg";
    case RTE_LOG_ALERT: return "alert";
    case RTE_LOG_CRIT: return "critical";
    case RTE_LOG_ERR: return "error";
    case RTE_LOG_WARNING: return "warning";
    case RTE_LOG_NOTICE: return "notice";
    case RTE_LOG_INFO: return "info";
    case RTE_LOG_DEBUG: return "debug";
    default: return "unknown";
    }
}

static const char *
logtype_to_string(uint32_t logtype, int i)
{
    switch (logtype) {
    case RTE_LOGTYPE_USER1: return "vrouter";
    case RTE_LOGTYPE_USER2: return "usock";
    case RTE_LOGTYPE_USER3: return "uvhost";
    case RTE_LOGTYPE_USER4: return "dpcore";
    default: return rte_logs.dynamic_types[i].name;
    }
}

int
dpdk_conf_log_list(VR_INFO_ARGS)
{
    VR_INFO_BUF_INIT();
    size_t i;
    VI_PRINTF("global log level is %s\n", loglevel_to_string(rte_log_get_global_level()));
    VI_PRINTF(" ------------------------------------------------------------ \n");
    VI_PRINTF("| ID |              LOGTYPE               |     LOGLEVEL     |\n");
    VI_PRINTF(" ------------------------------------------------------------ \n");
    for (i = 0; i < rte_logs.dynamic_types_len; i++) {
        if (rte_logs.dynamic_types[i].name == NULL)
            continue;
        if (i <= 9) {
            VI_PRINTF("|  %zu | %-34s | %-16s |", i, logtype_to_string(rte_log_register(rte_logs.dynamic_types[i].name),i),
            loglevel_to_string(rte_logs.dynamic_types[i].loglevel));
            VI_PRINTF("\n");
        }
        else {
            VI_PRINTF("| %zu | %-34s | %-16s |", i, logtype_to_string(rte_log_register(rte_logs.dynamic_types[i].name),i), 
            loglevel_to_string(rte_logs.dynamic_types[i].loglevel));
            VI_PRINTF("\n");
        }
    }
    VI_PRINTF(" ------------------------------------------------------------ \n");
    VI_PRINTF("\n");
    return 0;
}
