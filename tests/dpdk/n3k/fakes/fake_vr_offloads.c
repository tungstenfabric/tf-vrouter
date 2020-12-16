/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <vr_nexthop.h>
#include <vr_vxlan.h>
#include <vr_interface.h>

#include <cmocka.h>

struct vr_nexthop;
extern int __attribute__((weak)) vr_offloads_flow_set(struct vr_flow_entry *fe,
    unsigned int fe_index, struct vr_flow_entry *rfe);
extern int __attribute__((weak)) vr_offloads_flow_del(struct vr_flow_entry *fe);
extern int __attribute__((weak)) vr_offloads_interface_add(struct vr_interface *vif);
extern int __attribute__((weak)) vr_offloads_interface_del(struct vr_interface *vif);
extern uint32_t __attribute__((weak)) vr_n3k_translate_to_pid(struct vr_interface *vif);
extern int __attribute__((weak)) vr_offloads_mpls_add(struct vr_nexthop *nh, int label);
extern int __attribute__((weak)) vr_offloads_mpls_del(int label);
extern int __attribute__((weak)) vr_offloads_vxlan_add(struct vr_nexthop *nh, int vnid);
extern int __attribute__((weak)) vr_offloads_vxlan_del(int vnid);

/* TODO(n3k): Must be removed after reviewing route add/del */
int __attribute__((weak)) vr_bridge_entries;

int
vr_offloads_flow_set(
    struct vr_flow_entry * fe,
    unsigned int fe_index,
    struct vr_flow_entry * rfe)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int
vr_offloads_flow_del(struct vr_flow_entry * fe)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int
vr_offloads_interface_add(struct vr_interface *vif)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int
vr_offloads_interface_del(struct vr_interface *vif)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

uint32_t
vr_n3k_translate_to_pid(struct vr_interface *vif)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 1;
}

int
vr_offloads_mpls_add(struct vr_nexthop *nh, int label)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int
vr_offloads_mpls_del(int label)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int
vr_offloads_vxlan_add(struct vr_nexthop *nh, int vnid)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int
vr_offloads_vxlan_del(int vnid)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}
