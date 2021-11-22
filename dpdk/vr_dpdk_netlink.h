/*
 * vr_dpdk_netlink.h - header for vrouter DPDK netlink infrastructure.
 *
 *
 * Copyright (c) 2014 Juniper Networks, Inc. All rights reserved.
 */

#ifndef __VR_DPDK_NETLINK_H__
#define __VR_DPDK_NETLINK_H__

int vr_netlink_uvhost_vif_add(unsigned char *vif_name, uint32_t vif_idx,
                              uint32_t vif_gen, uint32_t vif_nrxqs,
                              uint32_t vif_ntxqs,
                              unsigned char vhostuser_mode);
int vr_netlink_uvhost_vif_del(unsigned int vif_idx);
int vr_dpdk_netlink_init(void);

#endif /* __VR_DPDK_NETLINK_H__ */
