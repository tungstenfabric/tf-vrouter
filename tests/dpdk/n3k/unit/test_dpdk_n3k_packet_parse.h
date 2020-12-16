/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef _TEST_DPDK_N3K_PACKET_PARSE_H_
#define _TEST_DPDK_N3K_PACKET_PARSE_H_

#include <vr_os.h>

#include <netinet/ether.h>
#include <netinet/in.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic error  "-Wpadded"

struct packet_udp_ipv4 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
} __attribute__((packed, aligned(2)));

static struct packet_udp_ipv4 test_udp_packets[] = {
    // Ethernet(type=IPv4)/IP(proto=UDP)/UDP()
    {
        .eth_hdr = {
            .s_addr = {
                .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 },
            },
            .d_addr = {
                .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 },
            },
            .ether_type = RTE_BE16(ETHERTYPE_IP),
        },
        .ipv4_hdr = {
            .version_ihl = RTE_IPV4_VHL_DEF,
            .next_proto_id = IPPROTO_UDP,
            .src_addr = RTE_IPV4(192, 168, 0, 1),
            .dst_addr = RTE_IPV4(192, 168, 0, 2),
        },
        .udp_hdr = {
            .src_port = RTE_BE16(5555),
            .dst_port = RTE_BE16(6666),
        },
    },

    // Ethernet(type=IPv6)
    {
        .eth_hdr = {
            .s_addr = {
                .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 },
            },
            .d_addr = {
                .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 },
            },
            .ether_type = RTE_BE16(ETHERTYPE_IPV6),
        },
    },

    // Ethernet(type=ARP)
    {
        .eth_hdr = {
            .s_addr = {
                .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 },
            },
            .d_addr = {
                .addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff },
            },
            .ether_type = RTE_BE16(ETHERTYPE_ARP),
        },
    },
};

struct packet_tcp_ipv4 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_tcp_hdr tcp_hdr;
} __attribute__((packed, aligned(2)));

static struct packet_tcp_ipv4 test_tcp_packets[] = {
    // Ethernet(type=IPv4)/IP(proto=TCP)/TCP()
    {
        .eth_hdr = {
            .s_addr = {
                .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 },
            },
            .d_addr = {
                .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 },
            },
            .ether_type = RTE_BE16(ETHERTYPE_IP),
        },
        .ipv4_hdr = {
            .version_ihl = RTE_IPV4_VHL_DEF,
            .next_proto_id = IPPROTO_TCP,
            .src_addr = RTE_IPV4(192, 168, 0, 1),
            .dst_addr = RTE_IPV4(192, 168, 0, 2),
        },
        .tcp_hdr = {
            .src_port = RTE_BE16(5555),
            .dst_port = RTE_BE16(6666),
        },
    },
};

struct packet_fabric_only_eth {
    struct rte_ether_hdr eth_hdr;
} __attribute__((packed, aligned(2)));

static struct packet_fabric_only_eth data_fabric_ether_ipv6_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IPV6),
    },
};

static struct packet_fabric_only_eth data_fabric_ether_arp_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_ARP),
    },
};

struct packet_fabric_only_ipv4 {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
} __attribute__((packed, aligned(2)));

static struct packet_fabric_only_ipv4 data_fabric_ipv4_gre_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_GRE,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
};

static struct packet_fabric_only_ipv4 data_fabric_ipv4_icmp_packet = {
    .eth_hdr = {
        .s_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x00, 0xaa, 0xaa, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IP),
    },
    .ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_ICMP,
        .src_addr = RTE_IPV4(2, 2, 2, 2),
        .dst_addr = RTE_IPV4(1, 1, 1, 1),
    },
};

struct packet_fabric_only_udp {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
} __attribute__((packed, aligned(2)));

static struct packet_fabric_only_udp data_fabric_ipv4_unknown_udp_packet = {
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
        .dst_port = RTE_BE16(12345),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
};

#pragma GCC diagnostic pop

#endif  //_TEST_DPDK_N3K_PACKET_PARSE_H_
