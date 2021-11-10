/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_ROUTE_H__
#define __VR_DPDK_N3K_ROUTE_H__

#include <rte_byteorder.h>

#include "vr_nexthop.h"
#include "vr_ip_mtrie.h"
#include "vr_datapath.h"

struct vr_n3k_offload_route_key {
    uint32_t vrf_id;
    enum vr_n3k_ip_type type;
    union vr_n3k_ip ip;
};

struct vr_n3k_offload_bridge_key {
    uint8_t mac[VR_ETHER_ALEN];
    uint32_t vrf_id;
};

struct vr_n3k_offload_bridge_value {
    uint32_t label;
    uint32_t nh_id;
};

struct vr_n3k_offload_route_value {
    uint32_t label;
    uint32_t nh_id;
};

static inline int
vr_dpdk_n3k_offload_route_find(struct vr_n3k_offload_route_key key,
    struct vr_n3k_offload_route_value *out_value) {
    bool ipv6_key = key.type == VR_N3K_IP_TYPE_IPV6;
    struct vr_route_req rtr = {
        .rtr_req = {
            .rtr_vrf_id = key.vrf_id,
            .rtr_family = ipv6_key ? AF_INET6 : AF_INET,
            .rtr_prefix_size = ipv6_key ? VR_IP6_ADDRESS_LEN : VR_IP_ADDRESS_LEN,
            .rtr_prefix_len = ipv6_key ? IP6_PREFIX_LEN : IP4_PREFIX_LEN,
            .rtr_prefix = ipv6_key ? (int8_t *)key.ip.ipv6 : (int8_t *)&key.ip.ipv4,
        },
    };
    struct vr_nexthop *nh = vr_inet_route_lookup(key.vrf_id, &rtr);

    if (!nh) {
        return -ENOENT;
    }

    out_value->nh_id = nh->nh_id;
    out_value->label = rtr.rtr_req.rtr_label;

    return 0;
}

static inline int
vr_dpdk_n3k_offload_bridge_find(const struct vr_n3k_offload_bridge_key *key,
    struct vr_n3k_offload_bridge_value *out_value) {

    struct vr_route_req rtr = {
        .rtr_req = {
            .rtr_vrf_id = key->vrf_id,
            .rtr_label_flags = 0,
            .rtr_index = VR_BE_INVALID_INDEX,
            .rtr_mac_size = VR_ETHER_ALEN,
            .rtr_mac = (int8_t*)&key->mac,
        }
    };

    /* Note: We're not handling multicast case specially, like
     * __vrouter_bridge_lookup does, as it's not supported by HW anyway */

    struct vr_nexthop* nh = vr_bridge_lookup(key->vrf_id, &rtr);

    if (!nh) {
        return -ENOENT;
    }

    out_value->nh_id = nh->nh_id;
    out_value->label = rtr.rtr_req.rtr_label;

    return 0;
}

#endif  // __VR_DPDK_N3K_ROUTE_H__
