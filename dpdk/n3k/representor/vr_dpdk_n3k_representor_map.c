/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include "vr_dpdk_n3k_representor_impl.h"

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_port_ethdev.h>

#define N3K_MAX_REPRESENTOR_COUNT 128
#define N3K_MAX_REPRESENTOR_COUNT_STRING RTE_STR(N3K_MAX_REPRESENTOR_COUNT)
#define N3K_REPRESENTOR_PREFIX "net_n3k0_vf"
#define N3K_REPRESENTOR_NAME_LENGTH \
    RTE_DIM(N3K_REPRESENTOR_PREFIX) + RTE_DIM(N3K_MAX_REPRESENTOR_COUNT_STRING)
#define N3K_REPRESENTOR_FIRST_VF_ID 1
#define N3K_REPRESENTOR_LAST_VF_ID N3K_MAX_REPRESENTOR_COUNT
#define N3K_REPRESENTOR_INVALID_VF_ID N3K_REPRESENTOR_LAST_VF_ID + 1

static struct vr_dpdk_n3k_representor_map_entry vif_to_repr_mapping[] = {
    [0 ... VR_MAX_INTERFACES] = {
        .id = N3K_REPRESENTOR_INVALID_VF_ID,
        .repr_name = NULL,
        .vif_name = NULL,
        .soft_reset = false,
    },
};

static const char *used_vfs[N3K_REPRESENTOR_INVALID_VF_ID] = {  0  };

static struct vr_dpdk_n3k_representor_map_entry
get_unused_n3k_repr(void)
{
    bool found = false;
    int did;
    uint16_t port_id;
    size_t i;
    char *repr_name = rte_malloc("n3k_repr_map_value",
        (N3K_REPRESENTOR_NAME_LENGTH + 1) * sizeof(*repr_name), 0);
    struct vr_dpdk_n3k_representor_map_entry ent = {
        .id = N3K_REPRESENTOR_INVALID_VF_ID,
        .repr_name = repr_name,
    };

    if (!repr_name) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error: memory allocation failed\n", __func__);
        return ent;
    }

    for (i = N3K_REPRESENTOR_FIRST_VF_ID; i < N3K_REPRESENTOR_INVALID_VF_ID; ++i) {
        int ret = snprintf(repr_name, N3K_REPRESENTOR_NAME_LENGTH,
                           N3K_REPRESENTOR_PREFIX "%zu", i);

        if (ret < 0 || ret > N3K_REPRESENTOR_NAME_LENGTH) {
            RTE_LOG(ERR, VROUTER,
                "%s(): string creation failed\n", __func__);
            goto cleanup;
        }

        ret = rte_eth_dev_get_port_by_name(repr_name, &port_id);
        did = rte_pmd_n3k_get_vdpa_did_by_repr_name(repr_name);
        if (ret == 0 && did >= 0 && used_vfs[i] == NULL) {
            found = true;
            break;
        }
    }

    if (found) {
        used_vfs[i] = ent.repr_name;
        ent.id = i;
    }

    return ent;
cleanup:
    rte_free(repr_name);
    ent.repr_name = NULL;
    return ent;
}

static void
put_unused_n3k_repr(struct vr_dpdk_n3k_representor_map_entry repr)
{
    if (repr.id >= N3K_REPRESENTOR_INVALID_VF_ID) {
        return;
    }

    rte_free((void *)used_vfs[repr.id]); //repr_name
    free((void *)repr.vif_name);

    used_vfs[repr.id] = NULL;
}

const char *
vr_dpdk_n3k_representor_map_create_entry(struct vr_interface *vif)
{
    struct vr_dpdk_n3k_representor_map_entry repr;
    if (vif == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): NULL vif name", __func__);
        return NULL;
    }

    repr = get_unused_n3k_repr();
    if (repr.id >= N3K_REPRESENTOR_INVALID_VF_ID) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error: No available VF found\n", __func__);
        return NULL;
    }

    repr.vif_name = strdup((const char *)vif->vif_name);
    if (repr.vif_name == NULL) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error: cannot duplicate vif name: %s", __func__, vif->vif_name);
        return NULL;
    }

    vif_to_repr_mapping[vif->vif_idx] = repr;

    return repr.repr_name;
}

struct vr_dpdk_n3k_representor_map_entry
vr_dpdk_n3k_representor_map_get_entry(struct vr_interface *vif)
{
    return vif_to_repr_mapping[vif->vif_idx];
}

void
vr_dpdk_n3k_representor_map_delete_entry(struct vr_interface *vif)
{
    struct vr_dpdk_n3k_representor_map_entry repr = vif_to_repr_mapping[vif->vif_idx];
    if (repr.id >= N3K_REPRESENTOR_INVALID_VF_ID) {
        RTE_LOG(WARNING, VROUTER,
            "%s(): was called, but no mapping for vif: %u exists\n",
            __func__, vif->vif_idx);
        return;
    }

    put_unused_n3k_repr(repr);
}

static void
vr_dpdk_n3k_representor_map_reset(void)
{
    int i = 0;
    for(; i < VR_MAX_INTERFACES; ++i) {
        if (vif_to_repr_mapping[i].vif_name) {
            vr_dpdk_n3k_vhost_unregister(vif_to_repr_mapping[i].vif_name);
        }
        put_unused_n3k_repr(vif_to_repr_mapping[i]);
        vif_to_repr_mapping[i].id = N3K_REPRESENTOR_INVALID_VF_ID;
        vif_to_repr_mapping[i].repr_name = NULL;
        vif_to_repr_mapping[i].vif_name = NULL;
        vif_to_repr_mapping[i].soft_reset = false;
    }
}

void
vr_dpdk_n3k_representor_map_entry_mark_soft_reset(struct vr_interface *vif)
{
    vif_to_repr_mapping[vif->vif_idx].soft_reset = true;
}

void
vr_dpdk_n3k_representor_map_entry_unmark_soft_reset(struct vr_interface *vif)
{
    vif_to_repr_mapping[vif->vif_idx].soft_reset = false;
}

int
vr_dpdk_n3k_representor_map_init(void)
{
    vr_dpdk_n3k_representor_map_reset();
    return 0;
}

void
vr_dpdk_n3k_representor_map_exit(void)
{
    vr_dpdk_n3k_representor_map_reset();
}
