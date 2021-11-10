/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#ifndef __VR_DPDK_N3K_PACKET_PARSER_H__
#define __VR_DPDK_N3K_PACKET_PARSER_H__

struct vr_packet;
struct vr_dpdk_n3k_packet_key;
struct vr_dpdk_n3k_packet_metadata;

int vr_dpdk_n3k_parse_packet(struct vr_packet *pkt,
        struct vr_dpdk_n3k_packet_key *key,
        struct vr_dpdk_n3k_packet_metadata *metadata);

#endif  // __VR_DPDK_N3K_PACKET_PARSER_H__
