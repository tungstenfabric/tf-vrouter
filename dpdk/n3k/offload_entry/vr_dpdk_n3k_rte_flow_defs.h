/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_RTE_FLOW_DEFS_H__
#define __VR_DPDK_N3K_RTE_FLOW_DEFS_H__

enum N3K_RTE_FLOW_PATTERN {
    PATTERN_PORT_ID,
    PATTERN_OUTER_ETH,
    PATTERN_OUTER_IPV4,
    PATTERN_OUTER_UDP,
    PATTERN_VXLAN,
    PATTERN_MPLS,
    PATTERN_ETH,
    PATTERN_IPV4,
    PATTERN_IPV6,
    PATTERN_UDP,
    PATTERN_TCP,
    PATTERN_END
};

enum N3K_RTE_FLOW_ACTION {
    ACTION_SET_SMAC,
    ACTION_SET_DMAC,

    ACTION_IPV4_SRC,

    ACTION_VXLAN_DECAP,
    ACTION_RAW_DECAP,
    ACTION_DEC_TTL,
    ACTION_VXLAN_ENCAP,
    ACTION_RAW_ENCAP,

    ACTION_IPV4_DST,

    ACTION_PORT_ID,
    ACTION_DROP,
    ACTION_MIRROR,
    ACTION_END
};

enum N3K_RTE_FLOW_ENCAP_PATTERN {
    ENCAP_ETH,
    ENCAP_IPV4,
    ENCAP_UDP,
    ENCAP_VXLAN,
    ENCAP_END
};

#endif // __VR_DPDK_N3K_RTE_FLOW_DEFS_H__
