/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "int_test_utils.h"
#include "int_test_utils_vxlan.h"

#include <setjmp.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <rte_memcpy.h>
#include <rte_debug.h>
#include <rte_malloc.h>

#include <cmocka.h>

struct vr_dpdk_n3k_packet_metadata create_packet_metadata_for_vxlan(
    uint8_t* overlay_src_mac,
    uint8_t* overlay_dst_mac,
    uint32_t src_ip,
    uint32_t dst_ip,
    uint8_t proto,
    uint16_t src_port,
    uint16_t dst_port,
    uint32_t nh_id
)
{
    struct vr_dpdk_n3k_packet_key packet_key =
        create_packet_key(src_ip, dst_ip, proto, src_port, dst_port, nh_id);
    struct vr_dpdk_n3k_packet_metadata packet_metadata;
    packet_metadata.eth_hdr_present = true;
    rte_memcpy(packet_metadata.inner_src_mac,
        overlay_src_mac, VR_ETHER_ALEN);
    rte_memcpy(packet_metadata.inner_dst_mac,
        overlay_dst_mac, VR_ETHER_ALEN);

    int ret = vr_dpdk_n3k_packet_metadata_insert_copy(
        &packet_key, &packet_metadata);
    assert_int_equal(ret, 0);
    return packet_metadata;
}

struct vr_n3k_offload_vxlan*
create_offload_vxlan(uint32_t vnid, uint32_t nexthop_id)
{
    struct vr_n3k_offload_vxlan *offload_vxlan
        = rte_zmalloc("n3k_offload_vxlan", sizeof(*offload_vxlan), 0);
    offload_vxlan->nexthop_id = nexthop_id;
    offload_vxlan->vnid = vnid;

    vr_dpdk_n3k_offload_vxlan_insert(offload_vxlan);

    assert_non_null(offload_vxlan);

    return offload_vxlan;
}

void
check_offload_entry_vxlan(
    struct vr_n3k_offload_entry *test_entry,
    struct vr_n3k_offload_entry *good_entry
)
{
    check_offload_entry(test_entry, good_entry);
    assert_int_equal(test_entry->tunnel_label, good_entry->tunnel_label);
}
