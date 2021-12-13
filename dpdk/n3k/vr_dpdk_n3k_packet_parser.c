/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_packet_parser.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <rte_byteorder.h>

#include <vr_dpdk.h>
#include <vr_nexthop.h>
#include <vr_packet.h>
#include <vr_route.h>
#include <vr_mpls.h>

#include "vr_dpdk_n3k_mpls.h"
#include "vr_dpdk_n3k_nexthop.h"
#include "vr_dpdk_n3k_packet_metadata.h"
#include "vr_dpdk_n3k_routes.h"
#include "vr_dpdk_n3k_vxlan.h"


struct vr_n3k_mpls {
    uint32_t mpls_hdr;
};

struct vr_n3k_packet_ip_package {
    uint8_t is_ipv6;
    union {
        struct vr_ip *ip_hdr;
        struct vr_ip6 *ip6_hdr;
    };
};

static uint8_t
vr_dpdk_n3k_parser_get_ip_proto(const struct vr_n3k_packet_ip_package *ip_pkg)
{
    return ip_pkg->is_ipv6
         ? ip_pkg->ip6_hdr->ip6_nxt
         : ip_pkg->ip_hdr->ip_proto;
}

struct vr_n3k_packet_ip_package
vr_dpdk_n3k_ip_package_set_ipv4(struct vr_ip *ip_hdr)
{
    return (struct vr_n3k_packet_ip_package) {
                .is_ipv6 = false, .ip_hdr = ip_hdr
            };
}

struct vr_n3k_packet_ip_package
vr_dpdk_n3k_ip_package_set_ipv6(struct vr_ip6 *ip6_hdr)
{
    struct vr_n3k_packet_ip_package hdr = {
        .is_ipv6 = true,
        .ip6_hdr = ip6_hdr,
    };
    return hdr;
}

uint8_t *
vr_dpdk_n3k_ip_package_get_next_hdr(struct vr_n3k_packet_ip_package *ip_pkg) {
    if (ip_pkg->is_ipv6) {
        return (uint8_t *)&ip_pkg->ip6_hdr[1];
    } else {
        return (uint8_t *)((uint8_t *)ip_pkg->ip_hdr +
                   ip_pkg->ip_hdr->ip_hl * 4);
    }
}

extern int __attribute__((weak))
    vr_dpdk_n3k_get_nh_from_vni_ipv4(const uint32_t vni, const rte_be32_t ip_addr,
            rte_le32_t *out_nh_id);

extern int __attribute__((weak))
    vr_dpdk_n3k_get_nh_from_vni_ipv6(const uint32_t vni, const uint8_t* ip_addr,
            rte_le32_t *out_nh_id);

extern int __attribute__((weak))
    vr_dpdk_n3k_is_nh_l2(uint32_t nh_id, bool *is_l2);

extern int __attribute__((weak))
    vr_dpdk_n3k_get_key_nh_from_l2_nh_ipv4(const uint32_t l2_nh_id,
        const rte_be32_t ip_addr, rte_le32_t *key_nh_id);

extern int __attribute__((weak))
    vr_dpdk_n3k_get_key_nh_from_l2_nh_ipv6(const uint32_t l2_nh_id,
        const uint8_t* ip_addr, rte_le32_t *key_nh_id);

static inline rte_le32_t vr_n3k_mpls_get_label(const struct vr_n3k_mpls *mpls)
{
    return rte_be_to_cpu_32(mpls->mpls_hdr) >> VR_MPLS_LABEL_SHIFT;
}

static inline rte_le32_t vr_n3k_mpls_get_bos(const struct vr_n3k_mpls *mpls)
{
    return rte_be_to_cpu_32(mpls->mpls_hdr) & VR_MPLS_STACK_BIT;
}

static int
convert_vni_to_vrf(const uint32_t vni, uint32_t *vrf)
{
    struct vr_n3k_offload_vxlan vxlan;
    const struct vr_nexthop *nh;
    int ret;

    if ((ret = vr_dpdk_n3k_offload_vxlan_get_by_vni(vni, &vxlan)) != 0)
        return ret;

    nh = vr_dpdk_n3k_offload_nexthop_get(vxlan.nexthop_id);
    if (nh == NULL || nh->nh_type != NH_VRF_TRANSLATE)
        return -ENOENT;

    *vrf = nh->nh_vrf;

    return 0;
}

int
vr_dpdk_n3k_get_nh_from_vni_ipv4(const uint32_t vni,
        const rte_be32_t ip_addr, rte_le32_t *out_nh_id)
{
    uint32_t vrf = 0;
    struct vr_n3k_offload_route_key key = {
        .type = VR_N3K_IP_TYPE_IPV4
    };
    struct vr_n3k_offload_route_value value;
    int ret;

    ret = convert_vni_to_vrf(vni, &vrf);
    if (ret < 0)
        return ret;

    key.ip.ipv4 = ip_addr;
    key.vrf_id = vrf;

    ret = vr_dpdk_n3k_offload_route_find(key, &value);
    if (ret < 0)
        return ret;

    *out_nh_id = value.nh_id;

    return 0;
}

int
vr_dpdk_n3k_get_nh_from_vni_ipv6(const uint32_t vni,
        const uint8_t* ip_addr, rte_le32_t *out_nh_id)
{
    uint32_t vrf = 0;
    struct vr_n3k_offload_route_key key = {
        .type = VR_N3K_IP_TYPE_IPV6
    };
    struct vr_n3k_offload_route_value value;
    int ret;

    ret = convert_vni_to_vrf(vni, &vrf);
    if (ret < 0)
        return ret;

    memcpy(key.ip.ipv6, ip_addr, VR_IP6_ADDRESS_LEN);
    key.vrf_id = vrf;

    ret = vr_dpdk_n3k_offload_route_find(key, &value);
    if (ret < 0)
        return ret;

    *out_nh_id = value.nh_id;

    return 0;
}

int
vr_dpdk_n3k_get_key_nh_from_l2_nh_ipv4(const uint32_t l2_nh_id,
    const rte_be32_t ip_addr, rte_le32_t *key_nh_id)
{
    const struct vr_nexthop *nh;
    struct vr_n3k_offload_route_key key = {
        .type = VR_N3K_IP_TYPE_IPV4
    };
    struct vr_n3k_offload_route_value value;
    int ret;

    nh = vr_dpdk_n3k_offload_nexthop_get(l2_nh_id);
    if (nh == NULL)
        return -ENOENT;

    key.ip.ipv4 = ip_addr;
    key.vrf_id = nh->nh_vrf;

    ret = vr_dpdk_n3k_offload_route_find(key, &value);
    if (ret < 0)
        return ret;

    *key_nh_id = value.nh_id;

    return 0;
}

int
vr_dpdk_n3k_get_key_nh_from_l2_nh_ipv6(const uint32_t l2_nh_id,
    const uint8_t* ip_addr, rte_le32_t *key_nh_id)
{
    const struct vr_nexthop *nh;
    struct vr_n3k_offload_route_key key = {
        .type = VR_N3K_IP_TYPE_IPV6
    };
    struct vr_n3k_offload_route_value value;
    int ret;

    nh = vr_dpdk_n3k_offload_nexthop_get(l2_nh_id);
    if (nh == NULL)
        return -ENOENT;

    memcpy(key.ip.ipv6, ip_addr, VR_IP6_ADDRESS_LEN);
    key.vrf_id = nh->nh_vrf;

    ret = vr_dpdk_n3k_offload_route_find(key, &value);
    if (ret < 0)
        return ret;

    *key_nh_id = value.nh_id;

    return 0;
}

int
vr_dpdk_n3k_is_nh_l2(uint32_t nh_id, bool *is_l2)
{
    const struct vr_nexthop *nh;

    nh = vr_dpdk_n3k_offload_nexthop_get(nh_id);
    if (nh == NULL)
        return -ENOENT;

    if (nh->nh_family == AF_BRIDGE)
        *is_l2 = true;
    else if (nh->nh_family == AF_INET)
        *is_l2 = false;
    else
        return -ENOTSUP;

    return 0;
}

static bool
is_inner_ether_type_supported(const struct vr_eth *eth_hdr)
{
    return eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP) ||
           eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP6);
}

static bool
is_inner_ip_proto_supported(uint8_t proto)
{
    return proto == IPPROTO_UDP || proto == IPPROTO_TCP;
}

static int
vr_dpdk_n3k_fill_packet_key_data(struct vr_dpdk_n3k_packet_key *key,
        rte_le32_t key_nh_id,
        struct vr_n3k_packet_ip_package *inner_ip_hdr)
{
    struct vr_udp *inner_udp_hdr;
    struct vr_tcp *inner_tcp_hdr;

    key->nh_id = key_nh_id;
    if (inner_ip_hdr->is_ipv6) {
        key->ip.type = VR_N3K_IP_TYPE_IPV6;
        memcpy(key->ip.src.ipv6, inner_ip_hdr->ip6_hdr->ip6_src,
           VR_IP6_ADDRESS_LEN);
        memcpy(key->ip.dst.ipv6, inner_ip_hdr->ip6_hdr->ip6_dst,
           VR_IP6_ADDRESS_LEN);
    } else {
        key->ip.type = VR_N3K_IP_TYPE_IPV4;
        key->ip.src.ipv4 = inner_ip_hdr->ip_hdr->ip_saddr;
        key->ip.dst.ipv4 = inner_ip_hdr->ip_hdr->ip_daddr;
    }
    key->proto = vr_dpdk_n3k_parser_get_ip_proto(inner_ip_hdr);

    uint8_t *l4_hdr = vr_dpdk_n3k_ip_package_get_next_hdr(inner_ip_hdr);

    switch (key->proto) {
    case VR_IP_PROTO_TCP:
        inner_tcp_hdr = (struct vr_tcp *)l4_hdr;
        key->src_port = inner_tcp_hdr->tcp_sport;
        key->dst_port = inner_tcp_hdr->tcp_dport;
        break;

    case VR_IP_PROTO_UDP:
        inner_udp_hdr = (struct vr_udp *)l4_hdr;
        key->src_port = inner_udp_hdr->udp_sport;
        key->dst_port = inner_udp_hdr->udp_dport;
        break;

    default:
        return -ENOSYS;
        break;
    }

    return 0;
}

static int
parse_packet_fabric_mpls(struct vr_n3k_mpls *mpls_hdr,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *mpls_md)
{
    struct vr_eth *inner_eth_hdr;
    struct vr_n3k_packet_ip_package inner_ip_hdr;

    struct vr_n3k_offload_mpls mpls_offload_data;
    rte_le32_t label;
    rte_le32_t key_nh_id = 0;

    int ret;
    bool is_l2;

    if (!vr_n3k_mpls_get_bos(mpls_hdr))
        return -ENOTSUP;

    label = vr_n3k_mpls_get_label(mpls_hdr);
    if (vr_dpdk_n3k_offload_mpls_get_by_label(label, &mpls_offload_data) != 0)
        return -ENOENT;

    ret = vr_dpdk_n3k_is_nh_l2(mpls_offload_data.nexthop_id, &is_l2);
    if (ret < 0)
        return ret;

    if (is_l2) {
        mpls_md->eth_hdr_present = true;

        inner_eth_hdr = (struct vr_eth *)(mpls_hdr + 1);
        memcpy(&mpls_md->inner_dst_mac[0], &inner_eth_hdr->eth_dmac[0], VR_ETHER_ALEN);
        memcpy(&mpls_md->inner_src_mac[0], &inner_eth_hdr->eth_smac[0], VR_ETHER_ALEN);

        if (!is_inner_ether_type_supported(inner_eth_hdr))
            return -ENOTSUP;

        if (inner_eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP)) {
            inner_ip_hdr = vr_dpdk_n3k_ip_package_set_ipv4(
                (struct vr_ip *)(inner_eth_hdr + 1));
            ret = vr_dpdk_n3k_get_key_nh_from_l2_nh_ipv4(
                mpls_offload_data.nexthop_id, inner_ip_hdr.ip_hdr->ip_daddr,
                &key_nh_id);
        } else if (inner_eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP6)) {
            inner_ip_hdr = vr_dpdk_n3k_ip_package_set_ipv6(
                (struct vr_ip6 *)(inner_eth_hdr + 1));
            ret = vr_dpdk_n3k_get_key_nh_from_l2_nh_ipv6(
                mpls_offload_data.nexthop_id, inner_ip_hdr.ip6_hdr->ip6_dst,
                &key_nh_id);
        }
        else
            return -EINVAL;

        if (ret < 0)
            return ret;
    } else {
        mpls_md->eth_hdr_present = false;
        if (vr_ip_is_ip4((struct vr_ip *)(mpls_hdr + 1)))
            inner_ip_hdr = vr_dpdk_n3k_ip_package_set_ipv4(
                (struct vr_ip *)(mpls_hdr + 1));
        else if (vr_ip_is_ip6((struct vr_ip *)(mpls_hdr + 1)))
            inner_ip_hdr = vr_dpdk_n3k_ip_package_set_ipv6(
                (struct vr_ip6 *)(mpls_hdr + 1));
        else
            return -EINVAL;

        key_nh_id = mpls_offload_data.nexthop_id;
    }

    if (!is_inner_ip_proto_supported(
            vr_dpdk_n3k_parser_get_ip_proto(&inner_ip_hdr)))
        return -ENOTSUP;


    ret = vr_dpdk_n3k_fill_packet_key_data(key, key_nh_id, &inner_ip_hdr);
    if (ret < 0)
        return ret;

    return 0;
}

static int
parse_packet_fabric_vxlan(struct vr_vxlan *vxlan_hdr,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *vxlan_md)
{
    struct vr_eth *inner_eth_hdr;
    struct vr_n3k_packet_ip_package inner_ip_hdr;

    rte_le32_t vxlan_vni;
    rte_le32_t key_nh_id = 0;

    int ret;

    vxlan_vni = rte_be_to_cpu_32(vxlan_hdr->vxlan_vnid) >> 8;

    inner_eth_hdr = (struct vr_eth *)(vxlan_hdr + 1);
    if (!is_inner_ether_type_supported(inner_eth_hdr))
        return -ENOTSUP;

    if (inner_eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP)) {
        inner_ip_hdr = vr_dpdk_n3k_ip_package_set_ipv4(
            (struct vr_ip *)(inner_eth_hdr + 1));
    } else if (inner_eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP6)) {
        inner_ip_hdr = vr_dpdk_n3k_ip_package_set_ipv6(
            (struct vr_ip6 *)(inner_eth_hdr + 1));
    } else
        return -EINVAL;

    if (!is_inner_ip_proto_supported(
            vr_dpdk_n3k_parser_get_ip_proto(&inner_ip_hdr)))
        return -ENOTSUP;

    if (inner_ip_hdr.is_ipv6)
        ret = vr_dpdk_n3k_get_nh_from_vni_ipv6(
            vxlan_vni, inner_ip_hdr.ip6_hdr->ip6_dst, &key_nh_id);
    else
        ret = vr_dpdk_n3k_get_nh_from_vni_ipv4(
            vxlan_vni, inner_ip_hdr.ip_hdr->ip_daddr, &key_nh_id);

    if (ret < 0)
        return ret;

    vxlan_md->eth_hdr_present = true;
    memcpy(&vxlan_md->inner_dst_mac[0], &inner_eth_hdr->eth_dmac[0], VR_ETHER_ALEN);
    memcpy(&vxlan_md->inner_src_mac[0], &inner_eth_hdr->eth_smac[0], VR_ETHER_ALEN);

    ret = vr_dpdk_n3k_fill_packet_key_data(key, key_nh_id, &inner_ip_hdr);
    if (ret < 0)
        return ret;

    return 0;
}

static int
parse_packet_fabric_gre(struct vr_packet *pkt,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *metadata)
{
    RTE_LOG(DEBUG, VROUTER, "%s(): called - unsupported\n", __func__);

    return -ENOSYS;
}

static int
parse_packet_fabric_udp(struct vr_udp *udp_pkt,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *udp_md)
{
    struct vr_vxlan *vxlan_hdr;
    struct vr_n3k_mpls *mpls_hdr;

    if (udp_pkt->udp_dport == rte_cpu_to_be_16(VR_MPLS_OVER_UDP_DST_PORT))
    {
        mpls_hdr = (struct vr_n3k_mpls *)(udp_pkt + 1);
        return parse_packet_fabric_mpls(mpls_hdr, key, udp_md);
    }

    if (udp_pkt->udp_dport == rte_cpu_to_be_16(VR_VXLAN_UDP_DST_PORT))
    {
        vxlan_hdr = (struct vr_vxlan *)(udp_pkt + 1);
        return parse_packet_fabric_vxlan(vxlan_hdr, key, udp_md);
    }

    return -EINVAL;
}

static int
parse_packet_fabric(struct vr_packet *pkt,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *fabric_md)
{
    struct vr_eth *outer_eth_hdr;
    struct vr_ip *outer_ip_hdr;
    struct vr_udp *outer_udp_hdr;

    outer_eth_hdr = (struct vr_eth *)pkt_data(pkt);
    if (outer_eth_hdr->eth_proto != rte_cpu_to_be_16(VR_ETH_PROTO_IP))
        return -EINVAL;

    outer_ip_hdr = (struct vr_ip *)(outer_eth_hdr + 1);

    if (outer_ip_hdr->ip_proto == VR_IP_PROTO_GRE)
    {
        return parse_packet_fabric_gre(pkt, key, fabric_md);
    }

    if (outer_ip_hdr->ip_proto == VR_IP_PROTO_UDP)
    {
        outer_udp_hdr = (struct vr_udp *)((uint8_t *)outer_ip_hdr + outer_ip_hdr->ip_hl * 4);
        return parse_packet_fabric_udp(outer_udp_hdr, key, fabric_md);
    }

    return -EINVAL;
}

static int
parse_packet_vm_rx(struct vr_packet *pkt,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *metadata)
{
    struct vr_eth *eth_hdr;
    struct vr_n3k_packet_ip_package ip_hdr;

    int ret;

    eth_hdr = (struct vr_eth *)pkt_data(pkt);
    if (!is_inner_ether_type_supported(eth_hdr))
        return -EINVAL;

    if (eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP)) {
        ip_hdr = vr_dpdk_n3k_ip_package_set_ipv4(
            (struct vr_ip *)(eth_hdr + 1));
    }
    else if (eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP6)) {
        ip_hdr = vr_dpdk_n3k_ip_package_set_ipv6(
            (struct vr_ip6 *)(eth_hdr + 1));
    }
    else
        return -EINVAL;

    metadata->eth_hdr_present = true;
    memcpy(&metadata->inner_dst_mac[0], &eth_hdr->eth_dmac[0], VR_ETHER_ALEN);
    memcpy(&metadata->inner_src_mac[0], &eth_hdr->eth_smac[0], VR_ETHER_ALEN);

    if (pkt->vp_priority != VP_PRIORITY_INVALID)
        metadata->tos = pkt->vp_priority;

    ret = vr_dpdk_n3k_fill_packet_key_data(key, pkt->vp_if->vif_nh_id, &ip_hdr);
    if (ret < 0)
        return ret;

    return 0;
}

int
vr_dpdk_n3k_parse_packet(struct vr_packet *pkt,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *metadata)
{
    assert(pkt != NULL);
    assert(pkt->vp_if != NULL);

    memset(key, 0, sizeof(*key));
    memset(metadata, 0, sizeof(*metadata));

    if (pkt->vp_if->vif_type == VIF_TYPE_PHYSICAL)
        return parse_packet_fabric(pkt, key, metadata);

    if ((pkt->vp_if->vif_type != VIF_TYPE_VIRTUAL) &&
            (pkt->vp_if->vif_type != VIF_TYPE_VIRTUAL_VLAN))
        return -EINVAL;

    return parse_packet_vm_rx(pkt, key, metadata);
}
