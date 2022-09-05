/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_NEXTHOP_H__
#define __VR_DPDK_N3K_NEXTHOP_H__

#include <rte_byteorder.h>
#include "vr_defs.h"
#include "vr_nexthop.h"
#include "vr_packet.h"

/* validates whether nexthop satisfies all the preconditions required by the
 * n3k offload module.
 *
 * @return
 *   0 on success
 *   -EAGAIN on detected concurrent modification
 *   -ENOENT on nh==NULL
 *   -ENOTSUP on other conditions
 */
int vr_dpdk_n3k_offload_nexthop_validate(const struct vr_nexthop* nh);

/* Note: Do not persist the returned pointer across the callback boundary.
 *
 * Returns NULL if the nexthop doesn't exists or fails validation (see
 * vr_dpdk_n3k_offload_nexthop_validate) */
const struct vr_nexthop * vr_dpdk_n3k_offload_nexthop_get(uint32_t id);

extern const uint8_t vr_n3k_offload_zero_mac[VR_ETHER_ALEN];

static const uint8_t get_first_valid_ecmp_index(const struct vr_nexthop* nh) {
    int i;
    for (i = 0; i < VR_MAX_PHY_INF; ++i) {
        if (!nh->nh_encap_valid[i])
            continue;
        return i;
    }
    return 0;
}

static inline const uint8_t nh_validate_underlay_index(const struct vr_nexthop* nh, int8_t underlay_ecmp_index) {
    if( !(nh->nh_flags & NH_FLAG_TUNNEL_UNDERLAY_ECMP) ) {
        return get_first_valid_ecmp_index(nh);
    }

    if( underlay_ecmp_index < 0 ) {
        return get_first_valid_ecmp_index(nh);
    }

    if( underlay_ecmp_index >= VR_MAX_PHY_INF ) {
        return get_first_valid_ecmp_index(nh);
    }

    if( !nh->nh_encap_valid[underlay_ecmp_index] ) {
        return get_first_valid_ecmp_index(nh);
    }

    return underlay_ecmp_index;
}

static inline const uint8_t *nh_src_mac(const struct vr_nexthop* nh, int8_t underlay_ecmp_index) {
    uint8_t loc_ecmp_index = nh_validate_underlay_index(nh, underlay_ecmp_index);

    if (nh->nh_data_size >= ((2 * VR_ETHER_ALEN)+(loc_ecmp_index*VR_ETHER_HLEN))) {
        struct vr_eth *eth = (struct vr_eth *)(nh->nh_data + (loc_ecmp_index*(VR_ETHER_HLEN)));
        return eth->eth_smac;
    } else {
        return vr_n3k_offload_zero_mac;
    }
}

static inline const uint8_t *nh_dst_mac(const struct vr_nexthop* nh, int8_t underlay_ecmp_index) {
    uint8_t loc_ecmp_index = nh_validate_underlay_index(nh, underlay_ecmp_index);

    if (nh->nh_data_size >= ((2 * VR_ETHER_ALEN)+(loc_ecmp_index*VR_ETHER_HLEN))) {
        struct vr_eth *eth = (struct vr_eth *)(nh->nh_data + (loc_ecmp_index*(VR_ETHER_HLEN)));
        return eth->eth_dmac;
    } else {
        return vr_n3k_offload_zero_mac;
    }
}

static inline rte_be32_t nh_tunnel_src_ip(const struct vr_nexthop* nh) {
    _Static_assert(
            offsetof(struct vr_nexthop, nh_udp_tun_sip) ==
            offsetof(struct vr_nexthop, nh_vxlan_tun_sip) &&
            offsetof(struct vr_nexthop, nh_gre_tun_sip) ==
            offsetof(struct vr_nexthop, nh_vxlan_tun_sip),
            "nh_vxlan_tun_sip can be used regardless of tunnel type");
    return nh->nh_type == NH_TUNNEL ? nh->nh_vxlan_tun_sip : 0;
}

static inline rte_be32_t nh_tunnel_dst_ip(const struct vr_nexthop* nh) {
    _Static_assert(
            offsetof(struct vr_nexthop, nh_udp_tun_dip) ==
            offsetof(struct vr_nexthop, nh_vxlan_tun_dip) &&
            offsetof(struct vr_nexthop, nh_gre_tun_dip) ==
            offsetof(struct vr_nexthop, nh_vxlan_tun_dip),
            "nh_vxlan_tun_dip can be used regardless of tunnel type");
    return nh->nh_type == NH_TUNNEL ? nh->nh_vxlan_tun_dip : 0;
}

static inline uint16_t nh_interface_id(const struct vr_nexthop* nh, int8_t underlay_ecmp_index) {
    uint8_t loc_ecmp_index = nh_validate_underlay_index(nh, underlay_ecmp_index);

    return nh->nh_dev_arr[loc_ecmp_index] != NULL ? nh->nh_dev_arr[loc_ecmp_index]->vif_idx : -1;
}

int vr_dpdk_n3k_offload_nexthop_get_cnh_idx(
    const struct vr_nexthop *nh, uint16_t idx, uint32_t *nh_idx);
int vr_dpdk_n3k_offload_nexthop_get_cnh_label(
    const struct vr_nexthop *nh, uint16_t idx, uint32_t *label);

#endif // __VR_DPDK_N3K_NEXTHOP_H__
