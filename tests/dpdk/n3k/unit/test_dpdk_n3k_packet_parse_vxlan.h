/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef _TEST_DPDK_N3K_PACKET_PARSE_VXLAN_H_
#define _TEST_DPDK_N3K_PACKET_PARSE_VXLAN_H_

#include <netinet/ether.h>
#include <netinet/in.h>

#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic error  "-Wpadded"

struct packet_vxlan_udp_ipv4 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_vxlan_hdr vxlan_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
    struct rte_udp_hdr inner_udp_hdr;
} __attribute__((packed));

static struct packet_vxlan_udp_ipv4 data_vxlan_udp_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
    .udp_hdr = {
        .src_port = RTE_BE16(12345),
        .dst_port = RTE_BE16(4789),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .vxlan_hdr = {
        .vx_flags = RTE_BE32(0x08000000),  // VNI=True, reserved=0
        .vx_vni = RTE_BE32(100 << 8),  // VNI=100
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .inner_ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(10, 0, 0, 2),
        .dst_addr = RTE_IPV4(10, 0, 0, 1),
    },
    .inner_udp_hdr = {
        .src_port = RTE_BE16(20000),
        .dst_port = RTE_BE16(10000),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
};

struct packet_vxlan_tcp_ipv4 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_vxlan_hdr vxlan_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
    struct rte_tcp_hdr inner_tcp_hdr;
} __attribute__((packed));

static struct packet_vxlan_tcp_ipv4 data_vxlan_tcp_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
    .udp_hdr = {
        .src_port = RTE_BE16(12345),
        .dst_port = RTE_BE16(4789),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .vxlan_hdr = {
        .vx_flags = RTE_BE32(0x08000000),  // VNI=True, reserved=0
        .vx_vni = RTE_BE32(100 << 8),  // VNI=100
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .inner_ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_TCP,
        .src_addr = RTE_IPV4(10, 0, 0, 2),
        .dst_addr = RTE_IPV4(10, 0, 0, 1),
    },
    .inner_tcp_hdr = {
        .src_port = RTE_BE16(20000),
        .dst_port = RTE_BE16(10000),
    },
};

struct packet_vxlan_only_inner_ipv4 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_vxlan_hdr vxlan_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
} __attribute__((packed));

static struct packet_vxlan_only_inner_ipv4 data_vxlan_ipv4_icmp_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
    .udp_hdr = {
        .src_port = RTE_BE16(12345),
        .dst_port = RTE_BE16(4789),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .vxlan_hdr = {
        .vx_flags = RTE_BE32(0x08000000),  // VNI=True, reserved=0
        .vx_vni = RTE_BE32(100 << 8),  // VNI=100
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .inner_ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_ICMP,
        .src_addr = RTE_IPV4(10, 0, 0, 2),
        .dst_addr = RTE_IPV4(10, 0, 0, 1),
    },
};

static struct packet_vxlan_only_inner_ipv4 data_vxlan_ipv4_sctp_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
    .udp_hdr = {
        .src_port = RTE_BE16(12345),
        .dst_port = RTE_BE16(4789),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .vxlan_hdr = {
        .vx_flags = RTE_BE32(0x08000000),  // VNI=True, reserved=0
        .vx_vni = RTE_BE32(100 << 8),  // VNI=100
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .inner_ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_SCTP,
        .src_addr = RTE_IPV4(10, 0, 0, 2),
        .dst_addr = RTE_IPV4(10, 0, 0, 1),
    },
};

struct packet_vxlan_only_inner_eth {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_vxlan_hdr vxlan_hdr;
    struct rte_ether_hdr inner_eth_hdr;
} __attribute__((packed));

static struct packet_vxlan_only_inner_eth data_vxlan_ether_arp_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
    .udp_hdr = {
        .src_port = RTE_BE16(12345),
        .dst_port = RTE_BE16(4789),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .vxlan_hdr = {
        .vx_flags = RTE_BE32(0x08000000),  // VNI=True, reserved=0
        .vx_vni = RTE_BE32(100 << 8),  // VNI=100
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_ARP),
    },
};

struct packet_vxlan_udp_ipv6 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_vxlan_hdr vxlan_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv6_hdr inner_ipv6_hdr;
    struct rte_udp_hdr inner_udp_hdr;
} __attribute__((packed));

static struct packet_vxlan_udp_ipv6 data_vxlan_udp_packet_ipv6 = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
    .udp_hdr = {
        .src_port = RTE_BE16(12345),
        .dst_port = RTE_BE16(4789),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .vxlan_hdr = {
        .vx_flags = RTE_BE32(0x08000000),  // VNI=True, reserved=0
        .vx_vni = RTE_BE32(100 << 8),  // VNI=100
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IPV6),
    },
    .inner_ipv6_hdr = {
        .vtc_flow = RTE_BE32(6 << 28),
        .proto = IPPROTO_UDP,
        .src_addr = "\x12\x10\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x04",
        .dst_addr = "\x12\x10\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x05",
    },
    .inner_udp_hdr = {
        .src_port = RTE_BE16(20000),
        .dst_port = RTE_BE16(10000),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
};

struct packet_vxlan_tcp_ipv6 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_vxlan_hdr vxlan_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv6_hdr inner_ipv6_hdr;
    struct rte_tcp_hdr inner_tcp_hdr;
} __attribute__((packed));

static struct packet_vxlan_tcp_ipv6 data_vxlan_tcp_packet_ipv6 = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
    .udp_hdr = {
        .src_port = RTE_BE16(12345),
        .dst_port = RTE_BE16(4789),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .vxlan_hdr = {
        .vx_flags = RTE_BE32(0x08000000),  // VNI=True, reserved=0
        .vx_vni = RTE_BE32(100 << 8),  // VNI=100
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IPV6),
    },
    .inner_ipv6_hdr = {
        .vtc_flow = RTE_BE32(6 << 28),
        .proto = IPPROTO_TCP,
        .src_addr = "\x12\x10\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x04",
        .dst_addr = "\x12\x10\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x05",
    },
    .inner_tcp_hdr = {
        .src_port = RTE_BE16(20000),
        .dst_port = RTE_BE16(10000),
    },
};

struct packet_vxlan_only_inner_ipv6 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_vxlan_hdr vxlan_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv6_hdr inner_ipv6_hdr;
} __attribute__((packed));

static struct packet_vxlan_only_inner_ipv6 data_vxlan_ipv6_icmpv6_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
    .udp_hdr = {
        .src_port = RTE_BE16(12345),
        .dst_port = RTE_BE16(4789),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .vxlan_hdr = {
        .vx_flags = RTE_BE32(0x08000000),  // VNI=True, reserved=0
        .vx_vni = RTE_BE32(100 << 8),  // VNI=100
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IPV6),
    },
    .inner_ipv6_hdr = {
        .vtc_flow = RTE_BE32(6 << 28),
        .proto = IPPROTO_ICMPV6,
        .src_addr = "\x12\x10\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x04",
        .dst_addr = "\x12\x10\x00\x00\x00\x00\x00\x00"
                    "\x00\x00\x00\x00\x00\x00\x00\x05",
    },
};

#pragma GCC diagnostic pop

#endif // _TEST_DPDK_N3K_PACKET_PARSE_VXLAN_H_
