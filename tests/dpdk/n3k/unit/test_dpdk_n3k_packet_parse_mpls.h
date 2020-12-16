/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef _TEST_DPDK_N3K_PACKET_PARSE_MPLS_H_
#define _TEST_DPDK_N3K_PACKET_PARSE_MPLS_H_

#include <netinet/ether.h>
#include <netinet/in.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_mpls.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic error  "-Wpadded"

struct packet_mpls_udp_eth_ipv4_udp {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
    struct rte_udp_hdr inner_udp_hdr;
} __attribute__((packed, aligned(2)));


struct packet_mpls_udp_ipv4_udp {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
    struct rte_udp_hdr inner_udp_hdr;
} __attribute__((packed, aligned(2)));


struct packet_mpls_udp_eth_ipv4_tcp {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
    struct rte_tcp_hdr inner_tcp_hdr;
} __attribute__((packed, aligned(2)));


struct packet_mpls_udp_ipv4_tcp {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
    struct rte_tcp_hdr inner_tcp_hdr;
} __attribute__((packed, aligned(2)));

struct packet_mpls_udp_eth_ipv4_only {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
    struct rte_ether_hdr inner_eth_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
} __attribute__((packed, aligned(2)));

struct packet_mpls_udp_ipv4_only {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
    struct rte_ipv4_hdr inner_ipv4_hdr;
} __attribute__((packed, aligned(2)));

struct packet_mpls_udp_eth_only {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
    struct rte_ether_hdr inner_eth_hdr;
} __attribute__((packed, aligned(2)));

struct packet_mpls_udp_ipv6_only {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
    struct rte_ipv6_hdr inner_ipv6_hdr;
} __attribute__((packed, aligned(2)));

struct packet_mpls_udp_only {
    struct rte_ether_hdr eth_hdr;
    struct rte_ipv4_hdr ipv4_hdr;
    struct rte_udp_hdr udp_hdr;
    struct rte_mpls_hdr mpls_hdr;
} __attribute__((packed, aligned(2)));

static struct packet_mpls_udp_eth_ipv4_udp data_mpls_udp_packet = {
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
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0xf,
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


static struct packet_mpls_udp_ipv4_udp data_mpls_udp_l3_packet = {
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
        .src_port = RTE_BE16(12000),
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0x0c,
    },
    .inner_ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_UDP,
        .src_addr = RTE_IPV4(192, 168, 0, 2),
        .dst_addr = RTE_IPV4(10, 0, 0, 1),
    },
    .inner_udp_hdr = {
        .src_port = RTE_BE16(20001),
        .dst_port = RTE_BE16(10001),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
};

static struct packet_mpls_udp_eth_ipv4_tcp data_mpls_tcp_packet = {
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
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0xf,
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
        .src_port = RTE_BE16(20002),
        .dst_port = RTE_BE16(10002),
    },
};


static struct packet_mpls_udp_ipv4_tcp data_mpls_tcp_l3_packet = {
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
        .src_port = RTE_BE16(12000),
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0x0c,
    },
    .inner_ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_TCP,
        .src_addr = RTE_IPV4(192, 168, 0, 2),
        .dst_addr = RTE_IPV4(10, 0, 0, 1),
    },
    .inner_tcp_hdr = {
        .src_port = RTE_BE16(20003),
        .dst_port = RTE_BE16(10003),
    },
};

static struct packet_mpls_udp_eth_ipv4_only data_mpls_ipv4_icmp_packet = {
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
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0xf,
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

static struct packet_mpls_udp_ipv4_only data_mpls_ipv4_icmp_l3_packet = {
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
        .src_port = RTE_BE16(12000),
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0x0c,
    },
    .inner_ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_ICMP,
        .src_addr = RTE_IPV4(192, 168, 0, 2),
        .dst_addr = RTE_IPV4(10, 0, 0, 1),
    },
};

static struct packet_mpls_udp_eth_ipv4_only data_mpls_ipv4_sctp_packet = {
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
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0xf,
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

static struct packet_mpls_udp_ipv4_only data_mpls_ipv4_sctp_l3_packet = {
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
        .src_port = RTE_BE16(12000),
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0x0c,
    },
    .inner_ipv4_hdr = {
        .version_ihl = RTE_IPV4_VHL_DEF,
        .next_proto_id = IPPROTO_SCTP,
        .src_addr = RTE_IPV4(192, 168, 0, 2),
        .dst_addr = RTE_IPV4(10, 0, 0, 1),
    },
};

static struct packet_mpls_udp_eth_only data_mpls_ipv4_arp_packet = {
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
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0xf,
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_ARP),
    },
};

static struct packet_mpls_udp_eth_only data_mpls_ipv6_packet = {
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
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0xf,
    },
    .inner_eth_hdr = {
        .s_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x02 } },
        .d_addr = { .addr_bytes = { 0x54, 0x52, 0x00, 0x00, 0x00, 0x01 } },
        .ether_type = RTE_BE16(ETHERTYPE_IPV6),
    },
};

static struct packet_mpls_udp_ipv6_only data_mpls_ipv6_l3_packet = {
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
        .src_port = RTE_BE16(12000),
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x1,
        .tag_lsb = 0x0c,
    },
    .inner_ipv6_hdr = {
        .vtc_flow = RTE_BE32((6 << 28)),
    },
};

static struct packet_mpls_udp_only data_mpls_not_bos_packet = {
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
        .src_port = RTE_BE16(12000),
        .dst_port = RTE_BE16(6635),
        .dgram_len = 0,  // TODO(n3k): fill...
        .dgram_cksum = 0,
    },
    .mpls_hdr = {
        .tag_msb = RTE_BE16(0x0001),
        .bs = 0x0,
        .tag_lsb = 0x0c,
    },
};

#pragma GCC diagnostic pop

#endif // _TEST_DPDK_N3K_PACKET_PARSE_MPLS_H_
