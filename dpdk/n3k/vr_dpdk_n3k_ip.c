/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <string.h>
#include <inttypes.h>
#include "vr_dpdk_n3k_ip.h"

const char *
vr_dpdk_n3k_convert_ip_to_str(char *buff, const union vr_n3k_ip *addr,
    const enum vr_n3k_ip_type ip_type)
{
    if (ip_type == VR_N3K_IP_TYPE_IPV4)
        sprintf(buff, IPV4_FORMAT, IPV4_VALUE(&addr->ipv4));
    else
        sprintf(buff, IPV6_FORMAT, IPV6_VALUE(addr->ipv6));
    return buff;
}
