/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_IP_H__
#define __VR_DPDK_N3K_IP_H__

#include <rte_byteorder.h>
#include <stdint.h>
#include "vr_flow.h"

enum vr_n3k_ip_type {
    VR_N3K_IP_TYPE_IPV4,
    VR_N3K_IP_TYPE_IPV6,
};

union vr_n3k_ip {
    rte_be32_t ipv4;
    uint8_t ipv6[VR_IP6_ADDRESS_LEN];
};

struct vr_n3k_ips {
    enum vr_n3k_ip_type type;
    union vr_n3k_ip src;
    union vr_n3k_ip dst;
};

// function doesn't check buff length
const char *
vr_dpdk_n3k_convert_ip_to_str(char *buff,
    const union vr_n3k_ip *addr,
    enum vr_n3k_ip_type ip_type);

#endif // __VR_DPDK_N3K_IP_H__
