/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_port_ethdev.h>

#include "vr_dpdk.h"
#include "vr_interface.h"

#include "vr_dpdk_n3k_representor_map.h"

#define N3K_MAX_REPRESENTOR_COUNT 128
#define N3K_MAX_REPRESENTOR_COUNT_STRING RTE_STR(N3K_MAX_REPRESENTOR_COUNT)
#define N3K_REPRESENTOR_PREFIX "net_n3k0_vf"
#define N3K_REPRESENTOR_NAME_LENGTH \
    RTE_DIM(N3K_REPRESENTOR_PREFIX) + RTE_DIM(N3K_MAX_REPRESENTOR_COUNT_STRING)
#define N3K_REPRESENTOR_FIRST_VF_ID 1
#define N3K_REPRESENTOR_LAST_VF_ID N3K_MAX_REPRESENTOR_COUNT
#define N3K_REPRESENTOR_INVALID_VF_ID N3K_REPRESENTOR_LAST_VF_ID + 1

struct n3k_representor_entry {
    uint16_t id;
    const char *name;
};

static struct n3k_representor_entry vif_to_repr_mapping[] = {
    [0 ... VR_MAX_INTERFACES] = { .id = N3K_REPRESENTOR_INVALID_VF_ID, .name = NULL },
};
static const char *used_vfs[N3K_REPRESENTOR_INVALID_VF_ID] = {  0  };

static struct n3k_representor_entry
get_unused_n3k_repr(void)
{
    bool found = false;
    char *name = rte_malloc("n3k_repr_map_value",
        N3K_REPRESENTOR_NAME_LENGTH + sizeof(*name), 0);
    struct n3k_representor_entry repr = {
        .id = N3K_REPRESENTOR_INVALID_VF_ID,
        .name = name,
    };
    if (!name) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error: memory allocation failed\n", __func__);
        return repr;
    }

    size_t i = N3K_REPRESENTOR_FIRST_VF_ID;
    for (; i < N3K_REPRESENTOR_INVALID_VF_ID; ++i) {
        int ret = snprintf(name, N3K_REPRESENTOR_NAME_LENGTH,
                           N3K_REPRESENTOR_PREFIX "%zu", i);

        if (ret < 0 || ret > N3K_REPRESENTOR_NAME_LENGTH) {
            RTE_LOG(ERR, VROUTER,
                "%s(): string creation failed\n", __func__);
            goto cleanup;
        }

        uint16_t port_id;
        ret = rte_eth_dev_get_port_by_name(name, &port_id);
        if (ret == 0 && used_vfs[i] == NULL) {
            found = true;
            break;
        }
    }

    if (found) {
        used_vfs[i] = repr.name;
        repr.id = i;
    }

    return repr;
cleanup:
    rte_free(name);
    repr.name = NULL;
    return repr;
}

static void
put_unused_n3k_repr(struct n3k_representor_entry repr)
{
    if (repr.id >= N3K_REPRESENTOR_INVALID_VF_ID) {
        return;
    }

    rte_free((void *)used_vfs[repr.id]);
    used_vfs[repr.id] = NULL;
}

const char *
vr_dpdk_n3k_representor_map_add(struct vr_interface *vif)
{
    struct n3k_representor_entry repr = get_unused_n3k_repr();
    if (repr.id >= N3K_REPRESENTOR_INVALID_VF_ID) {
        RTE_LOG(ERR, VROUTER,
            "%s(): error: Cannot get unused VF\n", __func__);
        return NULL;
    }

    vif_to_repr_mapping[vif->vif_idx] = repr;

    return repr.name;
}

void
vr_dpdk_n3k_representor_map_delete(struct vr_interface *vif)
{
    struct n3k_representor_entry repr = vif_to_repr_mapping[vif->vif_idx];
    if (repr.id >= N3K_REPRESENTOR_INVALID_VF_ID) {
        RTE_LOG(WARNING, VROUTER,
            "%s(): was called, but no mapping for vif: %s exists\n",
            __func__, vif->vif_name);
        return;
    }

    put_unused_n3k_repr(repr);
}

static void
vr_dpdk_n3k_representor_map_reset(void)
{
    int i = 0;
    for(; i < VR_MAX_INTERFACES; ++i) {
        put_unused_n3k_repr(vif_to_repr_mapping[i]);
        vif_to_repr_mapping[i].id = N3K_REPRESENTOR_INVALID_VF_ID;
        vif_to_repr_mapping[i].name = NULL;
    }
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
