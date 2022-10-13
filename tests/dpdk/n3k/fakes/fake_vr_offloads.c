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
#include "vr_mirror.h"

#include <cmocka.h>
#include <rte_malloc.h>

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
extern nh_processing_t __attribute__((weak)) nh_discard(struct vr_packet *pkt, struct vr_nexthop *nh, struct vr_forwarding_md *fmd);
extern struct vrouter * __attribute__((weak)) vrouter_get(unsigned int vr_id);
extern struct vr_nexthop * __attribute__((weak)) __vrouter_get_nexthop(struct vrouter *router, unsigned int index);
extern void vr_compute_size_oflow_table(void);

size_t __attribute__((weak)) vr_dpdk_lcore_free_lcore_get(void);
int __attribute__((weak)) vr_htable_trav(vr_htable_t, unsigned int , htable_trav_cb , void *);
void __attribute__((weak)) update_flow_entry(vr_htable_t table __attribute__unused__, vr_hentry_t *ent,
        unsigned int index, void *data __attribute__unused__);

struct vr_offload_ops;
int __attribute__((weak)) vr_offload_register(const struct vr_offload_ops *new_handler);
int __attribute__((weak)) vr_offload_unregister(void);
extern struct vr_interface *__vrouter_get_interface(struct vrouter *, unsigned int);


unsigned int __attribute__((weak)) datapath_offloads;
unsigned int __attribute__((weak)) vr_flow_entries = VR_DEF_FLOW_ENTRIES;
unsigned int __attribute__((weak)) vr_oflow_entries = VR_DEF_FLOW_ENTRIES / 5;

static size_t vr_interface_count = 0;
static struct vr_interface **interfaces;

struct vr_interface *
__vrouter_get_interface(struct vrouter *vrouter, unsigned int index)
{
    if (index >= vr_interface_count || !interfaces[index]) {
        return NULL;
    }
    return interfaces[index];
}

int
mock_vr_dpdk_n3k_offload_interface_init(uint32_t count)
{
    interfaces = (struct vr_interface **)rte_zmalloc(
        "vr_interfaces", count * sizeof(struct vr_interface *), 0);
    if (interfaces == NULL)
        return -ENOMEM;
    vr_interface_count = count;
    return 0;
}

void
mock_vr_dpdk_n3k_offload_interface_insert(struct vr_interface *vif)
{
    interfaces[vif->vif_idx] = vif;
}

void
mock_vr_dpdk_n3k_offload_interface_exit()
{
    int idx;
    for (idx = 0; idx < vr_interface_count; ++idx) {
        rte_free(interfaces[idx]);
        interfaces[idx] = NULL;
    }

    rte_free(interfaces);
    interfaces = NULL;
    vr_interface_count = 0;
}

int
vr_offload_register(const struct vr_offload_ops *new_handler)
{
    return 0;
}

int
vr_offload_unregister(void)
{
    return 0;
}

struct vr_mirror_entry *vrouter_get_mirror(unsigned int rid, unsigned int index);

#define MAX_MIRRORS 100
static struct vr_mirror_entry mirrors[MAX_MIRRORS];

struct vr_mirror_entry *
vrouter_get_mirror(unsigned int rid, unsigned int index)
{
    if (index >= MAX_MIRRORS)
        return NULL;

    return &mirrors[index];
}

void vr_dpdk_n3k_test_reset_mirrors()
{
    memset(mirrors, 0, MAX_MIRRORS * sizeof(struct vr_mirror_entry));
}

static uint32_t mock_nexthops_count;
static struct vr_nexthop **mock_nexthops;

struct vrouter {};

size_t
vr_dpdk_lcore_free_lcore_get(void)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int
vr_htable_trav(vr_htable_t htable, unsigned int marker, htable_trav_cb cb, void *data)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

void
update_flow_entry(vr_htable_t table __attribute__unused__, vr_hentry_t *ent,
        unsigned int index, void *data __attribute__unused__)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
}

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


nh_processing_t
nh_discard(struct vr_packet *pkt, struct vr_nexthop *nh,
	   struct vr_forwarding_md *fmd)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

struct vrouter *
vrouter_get(unsigned int vr_id)
{
    static struct vrouter mock_vrouter;
    return &mock_vrouter;
}

void
vr_compute_size_oflow_table(void)
{

}

struct vr_nexthop *
__vrouter_get_nexthop(struct vrouter *router, unsigned int index)
{
    if (index >= mock_nexthops_count || !mock_nexthops[index]) {
        return NULL;
    }
    return mock_nexthops[index];
}

int
mock_vr_dpdk_n3k_offload_nexthop_insert(struct vr_nexthop *nh)
{
    mock_nexthops[nh->nh_id] = nh;
    return 0;
}

int
mock_vr_dpdk_n3k_offload_nexthop_init(uint32_t count)
{
    mock_nexthops = (struct vr_nexthop **)rte_zmalloc("vr_nexthop", count * sizeof(struct vr_nexthop *), 0);
    if (mock_nexthops == NULL)
        return -ENOMEM;

    mock_nexthops_count = count;

    return 0;
}

void
mock_vr_dpdk_n3k_offload_nexthop_exit(void)
{
    int idx;

    for (idx = 0; idx < mock_nexthops_count; ++idx) {
        if(!mock_nexthops[idx]){
            continue;
        }
        rte_free(mock_nexthops[idx]->nh_dev);
        if(mock_nexthops[idx]->nh_type == NH_COMPOSITE) {
            rte_free(mock_nexthops[idx]->nh_u.nh_composite.component);
        }
        rte_free(mock_nexthops[idx]);
        mock_nexthops[idx] = NULL;
    }

    rte_free(mock_nexthops);
    mock_nexthops = NULL;
}
