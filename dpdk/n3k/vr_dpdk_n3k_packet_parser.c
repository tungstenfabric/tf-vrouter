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

extern int __attribute__((weak))
    vr_dpdk_n3k_get_nh_from_vni_ipv4(const uint32_t vni, const rte_be32_t ip_addr,
            rte_le32_t *out_nh_id);

extern int __attribute__((weak))
    vr_dpdk_n3k_is_nh_l2(uint32_t nh_id, bool *is_l2);

extern int __attribute__((weak))
    vr_dpdk_n3k_get_key_nh_from_l2_nh(const uint32_t l2_nh_id,
        const rte_be32_t ip_addr, rte_le32_t *key_nh_id);

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
    struct vr_n3k_offload_vxlan *vxlan;
    struct vr_n3k_offload_nexthop *nh;

    vxlan = vr_dpdk_n3k_offload_vxlan_get_by_vni(vni);
    if (vxlan == NULL)
        return -ENOENT;

    nh = vr_dpdk_n3k_offload_nexthop_get(vxlan->nexthop_id);
    if (nh == NULL || nh->type != NH_VRF_TRANSLATE)
        return -ENOENT;

    *vrf = nh->vrf;

    return 0;
}

int
vr_dpdk_n3k_get_nh_from_vni_ipv4(const uint32_t vni,
        const rte_be32_t ip_addr, rte_le32_t *out_nh_id)
{
    uint32_t vrf = 0;
    struct vr_n3k_offload_route_key key = { 0 };
    struct vr_n3k_offload_route_value value;
    int ret;

    ret = convert_vni_to_vrf(vni, &vrf);
    if (ret < 0)
        return ret;

    key.ip = ip_addr;
    key.vrf_id = vrf;

    ret = vr_dpdk_n3k_offload_route_find(&key, &value);
    if (ret < 0)
        return ret;

    *out_nh_id = value.nh_id;

    return 0;
}

int
vr_dpdk_n3k_get_key_nh_from_l2_nh(const uint32_t l2_nh_id,
        const rte_be32_t ip_addr, rte_le32_t *key_nh_id)
{
    struct vr_n3k_offload_nexthop *nh;
    struct vr_n3k_offload_route_key key = { 0 };
    struct vr_n3k_offload_route_value value;
    int ret;

    nh = vr_dpdk_n3k_offload_nexthop_get(l2_nh_id);
    if (nh == NULL)
        return -ENOENT;

    key.ip = ip_addr;
    key.vrf_id = nh->vrf;

    ret = vr_dpdk_n3k_offload_route_find(&key, &value);
    if (ret < 0)
        return ret;

    *key_nh_id = value.nh_id;

    return 0;
}

int
vr_dpdk_n3k_is_nh_l2(uint32_t nh_id, bool *is_l2)
{
    struct vr_n3k_offload_nexthop *nh;

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
    return eth_hdr->eth_proto == rte_cpu_to_be_16(VR_ETH_PROTO_IP);
}

static bool
is_inner_ipv4_proto_supported(const struct vr_ip *ip_hdr)
{
    return ip_hdr->ip_proto == IPPROTO_UDP || ip_hdr->ip_proto == IPPROTO_TCP;
}

static int
vr_dpdk_n3k_fill_packet_key_data(struct vr_dpdk_n3k_packet_key *key,
        rte_le32_t key_nh_id,
        const struct vr_ip *inner_ip_hdr)
{
    struct vr_udp *inner_udp_hdr;
    struct vr_tcp *inner_tcp_hdr;

    key->nh_id = key_nh_id;
    key->src_ip = inner_ip_hdr->ip_saddr;
    key->dst_ip = inner_ip_hdr->ip_daddr;
    key->proto = inner_ip_hdr->ip_proto;

    uint8_t *l4_hdr = (uint8_t *)inner_ip_hdr + inner_ip_hdr->ip_hl * 4;

    switch (inner_ip_hdr->ip_proto) {
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
    struct vr_ip *inner_ip_hdr;
    struct vr_n3k_offload_mpls *mpls_offload_data;
    rte_le32_t label;
    rte_le32_t key_nh_id = 0;

    int ret;
    bool is_l2;

    if (!vr_n3k_mpls_get_bos(mpls_hdr))
        return -ENOTSUP;

    label = vr_n3k_mpls_get_label(mpls_hdr);
    mpls_offload_data = vr_dpdk_n3k_offload_mpls_get_by_label(label);
    if (mpls_offload_data == NULL)
        return -ENOENT;

    ret = vr_dpdk_n3k_is_nh_l2(mpls_offload_data->nexthop_id, &is_l2);
    if (ret < 0)
        return ret;

    if (is_l2) {
        mpls_md->eth_hdr_present = true;

        inner_eth_hdr = (struct vr_eth *)(mpls_hdr + 1);
        memcpy(&mpls_md->inner_dst_mac[0], &inner_eth_hdr->eth_dmac[0], VR_ETHER_ALEN);
        memcpy(&mpls_md->inner_src_mac[0], &inner_eth_hdr->eth_smac[0], VR_ETHER_ALEN);

        if (!is_inner_ether_type_supported(inner_eth_hdr))
            return -ENOTSUP;

        inner_ip_hdr = (struct vr_ip *)(inner_eth_hdr + 1);

        ret = vr_dpdk_n3k_get_key_nh_from_l2_nh(mpls_offload_data->nexthop_id, inner_ip_hdr->ip_daddr, &key_nh_id);
        if (ret < 0)
            return ret;
    } else {
        mpls_md->eth_hdr_present = false;

        inner_ip_hdr = (struct vr_ip *)(mpls_hdr + 1);
        if (!vr_ip_is_ip4(inner_ip_hdr))
            return -ENOTSUP;

        key_nh_id = mpls_offload_data->nexthop_id;
    }

    if (!is_inner_ipv4_proto_supported(inner_ip_hdr))
        return -ENOTSUP;


    ret = vr_dpdk_n3k_fill_packet_key_data(key, key_nh_id, inner_ip_hdr);
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
    struct vr_ip *inner_ip_hdr;

    rte_le32_t vxlan_vni;
    rte_le32_t key_nh_id = 0;

    int ret;

    vxlan_vni = rte_be_to_cpu_32(vxlan_hdr->vxlan_vnid) >> 8;

    inner_eth_hdr = (struct vr_eth *)(vxlan_hdr + 1);
    if (!is_inner_ether_type_supported(inner_eth_hdr))
        return -ENOTSUP;

    inner_ip_hdr = (struct vr_ip *)(inner_eth_hdr + 1);

    if (!is_inner_ipv4_proto_supported(inner_ip_hdr))
        return -ENOTSUP;

    ret = vr_dpdk_n3k_get_nh_from_vni_ipv4(vxlan_vni, inner_ip_hdr->ip_daddr, &key_nh_id);
    if (ret < 0)
        return ret;

    vxlan_md->eth_hdr_present = true;
    memcpy(&vxlan_md->inner_dst_mac[0], &inner_eth_hdr->eth_dmac[0], VR_ETHER_ALEN);
    memcpy(&vxlan_md->inner_src_mac[0], &inner_eth_hdr->eth_smac[0], VR_ETHER_ALEN);

    ret = vr_dpdk_n3k_fill_packet_key_data(key, key_nh_id, inner_ip_hdr);
    if (ret < 0)
        return ret;

    return 0;
}

static int
parse_packet_fabric_gre(struct vr_packet *pkt,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *metadata)
{
    // TODO(smartnic): Implement for MPLSoGRE;
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
    struct vr_ip *ip_hdr;

    int ret;

    eth_hdr = (struct vr_eth *)pkt_data(pkt);
    if (eth_hdr->eth_proto != rte_cpu_to_be_16(VR_ETH_PROTO_IP))
        return -EINVAL;

    ip_hdr = (struct vr_ip *)(eth_hdr + 1);

    metadata->eth_hdr_present = true;
    memcpy(&metadata->inner_dst_mac[0], &eth_hdr->eth_dmac[0], VR_ETHER_ALEN);
    memcpy(&metadata->inner_src_mac[0], &eth_hdr->eth_smac[0], VR_ETHER_ALEN);

    ret = vr_dpdk_n3k_fill_packet_key_data(key, pkt->vp_if->vif_nh_id, ip_hdr);
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

    if (pkt->vp_if->vif_type != VIF_TYPE_VIRTUAL)
        return -EINVAL;

    return parse_packet_vm_rx(pkt, key, metadata);
}
