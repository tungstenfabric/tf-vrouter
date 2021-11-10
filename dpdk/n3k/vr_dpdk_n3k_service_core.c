/* SPDX-License-Identifier: BSD-2-Clause
 * Copyright(c) HCL TECHNOLOGIES LTD
 * Submitted on behalf of a third-party: Intel Corporation, a
 * Delaware corporation, having its principal place of business
 * at 2200 Mission College Boulevard,
 * Santa Clara, California 95052, USA
 */

#include <assert.h>
#include <errno.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_service.h>
#include <rte_service_component.h>
#include <string.h>

#include "../vr_dpdk_pmd_context.h"
#include "vr_dpdk.h"
#include "vr_dpdk_n3k_config.h"
#include "vr_dpdk_n3k_service_core.h"
#include "vr_dpdk_n3k_packet_metadata.h"
#include "vr_flow.h"
#include "vrouter.h"

typedef int (*n3k_service_core_routine_t)(void *);
typedef bool (*n3k_service_core_enabled_check_cb_t)(void);
struct vr_dpdk_n3k_service_core {
    const char *name;
    int32_t mapped_lcore_id;
    n3k_service_core_routine_t routine;
    n3k_service_core_enabled_check_cb_t enabled_check_cb;
    uint32_t service_id;
    bool disabled;
};

#define VR_DPDK_N3K_SERVICE_CORE_INITIALIZER(                                  \
  service_core_name, check, routine_name, is_disabled)                         \
    {                                                                          \
        .name = #service_core_name, .mapped_lcore_id = -1,                     \
        .routine = (routine_name), .enabled_check_cb = (check),                \
        .service_id = (uint32_t)-1,  .disabled = (is_disabled)                 \
    }

static void
n3k_fe_update(vr_htable_t table,
              vr_hentry_t *ent,
              unsigned int index,
              void *data)
{
    if (ent == NULL)
        return;

    rte_delay_us_sleep(30);

    update_flow_entry(table, ent, index, data);
}

static int
aging_service_core(__attribute__((unused)) void *userdata)
{
    struct vrouter *router = vrouter_get(0);

    // update vrouter statistics from HW
    vr_htable_trav(router->vr_flow_table, 0, n3k_fe_update, NULL);

    return 0;
}

static int
remove_unused_metadata_service_core(__attribute__((unused)) void *userdata)
{
    vr_dpdk_n3k_packet_metadata_remove_unused();

    // Some sort of pause is needed as the function above holds lock
    // on the hashmap containing metadatas and it affects performance of
    // the packet processing
    sleep(VR_DPDK_N3K_PACKET_METADATA_TIMEOUT);

    return 0;
}

struct vr_dpdk_n3k_service_core n3k_service_cores[] = {
    VR_DPDK_N3K_SERVICE_CORE_INITIALIZER(mp_service, NULL, NULL, false),
    VR_DPDK_N3K_SERVICE_CORE_INITIALIZER(dispatcher, NULL, NULL, false),
    VR_DPDK_N3K_SERVICE_CORE_INITIALIZER(
      n3k_aging_service_core,
      vr_dpdk_n3k_config_is_aging_service_core_enabled,
      aging_service_core,
      false),
    VR_DPDK_N3K_SERVICE_CORE_INITIALIZER(
      n3k_remove_unused_metadata_service_core,
      NULL,
      remove_unused_metadata_service_core,
      false),
    VR_DPDK_N3K_SERVICE_CORE_INITIALIZER(flr_service, NULL, NULL, true),
};

static bool
is_service_core_enabled(struct vr_dpdk_n3k_service_core *service_core)
{
    return !service_core->enabled_check_cb || service_core->enabled_check_cb();
}

#define FOREACH_ENABLED_N3K_SERVICE_CORE(iter, ptr)                            \
    size_t (iter) = 0;                                                         \
    struct vr_dpdk_n3k_service_core *(ptr) = &n3k_service_cores[(iter)];       \
    for (; (iter) < RTE_DIM(n3k_service_cores); ++(iter), ++(ptr))             \
        if (is_service_core_enabled((ptr)) && !ptr->disabled)

static size_t
get_enabled_n3k_service_core_count(void)
{
    size_t count = 0;

    FOREACH_ENABLED_N3K_SERVICE_CORE(i, service_core) {
        count++;
    }

    return count;
}

static void
set_n3k_service_core_mapping(size_t first_free_lcore_id)
{
    size_t lcore_id = first_free_lcore_id;

    FOREACH_ENABLED_N3K_SERVICE_CORE(i, service_core) {
        service_core->mapped_lcore_id = lcore_id++;
    }
}

static int
get_service_id(struct vr_dpdk_n3k_service_core *service_core)
{
    uint32_t id = 0;

    for (; id < rte_service_get_count(); ++id) {
        const char *name = rte_service_get_name(id);
        if (strstr(name, service_core->name)) {
            service_core->service_id = id;
            return 0;
        }
    }

    RTE_LOG(ERR,
            VROUTER,
            "N3K service_core: Could not get id of service %s\n",
            service_core->name);

    return -EINVAL;
}

static int
register_service(struct vr_dpdk_n3k_service_core *service_core)
{
    struct rte_service_spec spec = {{0}};

    strncpy(spec.name, service_core->name, RTE_DIM(spec.name) - 1);
    spec.callback = service_core->routine;
    /* TODO: Set spec.socket_id properly */

    int ret = rte_service_component_register(&spec, &service_core->service_id);
    if (ret) {
        RTE_LOG(ERR,
                VROUTER,
                "N3K service_core: Could not register service %sd\n",
                service_core->name);
        return ret;
    }

    rte_service_component_runstate_set(service_core->service_id, 1);

    return 0;
}

void
vr_dpdk_n3k_service_core_flr_sim_enable(void)
{
    size_t i;
    for (i = 0; i < RTE_DIM(n3k_service_cores); ++i) {
        struct vr_dpdk_n3k_service_core *service_core = &n3k_service_cores[i];
        if (strcmp("flr_service", service_core->name) != 0)
            continue;
        service_core->disabled = false;
    }
}

int
vr_dpdk_n3k_service_core_init(void)
{
    if (!vr_dpdk_n3k_config_is_n3k_enabled()) {
        return 0;
    }

    FOREACH_ENABLED_N3K_SERVICE_CORE(i, service_core) {
        int ret = service_core->routine ? register_service(service_core)
                                        : get_service_id(service_core);

        if (ret) {
            RTE_LOG(ERR,
                    VROUTER,
                    "N3K service_core: Service core initialization failed\n");
            return ret;
        }
    }

    return 0;
}

int
vr_dpdk_n3k_service_core_exit(void)
{
    if (!vr_dpdk_n3k_config_is_n3k_enabled()) {
        return 0;
    }

    FOREACH_ENABLED_N3K_SERVICE_CORE(i, service_core) {
        if (service_core->routine && service_core->service_id != (uint32_t)-1) {
            rte_service_component_runstate_set(service_core->service_id, 0);

            int ret =
              rte_service_component_unregister(service_core->service_id);
            if (ret) {
                RTE_LOG(ERR,
                        VROUTER,
                        "N3K service_core: Could not unregister service "
                        "component %s "
                        "id: %u \n",
                        service_core->name,
                        service_core->service_id);
                return ret;
            }
        }
    }

    return 0;
}

int
vr_dpdk_n3k_service_core_lcore_request(char *lcores_str,
                                       size_t lcores_str_sz,
                                       char *service_core_cpu_mapping_str)
{
    if (!vr_dpdk_n3k_config_is_n3k_enabled()) {
        return 0;
    }

    char n3k_lcores_str[VR_DPDK_STR_BUF_SZ];
    size_t n3k_lcores_str_sz = RTE_DIM(n3k_lcores_str);
    size_t free_lcore_id = vr_dpdk_lcore_free_lcore_get();
    size_t n3k_service_core_count = get_enabled_n3k_service_core_count();

    int ret = snprintf(n3k_lcores_str,
                       n3k_lcores_str_sz,
                       ",(%zu-%zu)@%s",
                       free_lcore_id,
                       free_lcore_id + n3k_service_core_count - 1,
                       service_core_cpu_mapping_str);
    if (ret < 0 || ret >= n3k_lcores_str_sz) {
        RTE_LOG(
          ERR,
          VROUTER,
          "N3K service_core: Could not create n3k lcore mapping string\n");
        return -EINVAL;
    }

    strncat(lcores_str,
            n3k_lcores_str,
            lcores_str_sz - strlen(n3k_lcores_str) - strlen(lcores_str));

    set_n3k_service_core_mapping(free_lcore_id);

    return 0;
}

int
vr_dpdk_n3k_service_core_stop(void)
{
    if (!vr_dpdk_n3k_config_is_n3k_enabled()) {
        return 0;
    }

    FOREACH_ENABLED_N3K_SERVICE_CORE(i, service_core) {
        int ret = rte_service_runstate_set(service_core->service_id, 0);
        if (ret) {
            RTE_LOG(
              ERR,
              VROUTER,
              "N3K service_core: Could not set service runstate %s id: %u \n",
              service_core->name,
              service_core->service_id);
            return -ENOEXEC;
        }

        ret = rte_service_map_lcore_set(
          service_core->service_id, service_core->mapped_lcore_id, 0);
        if (ret) {
            RTE_LOG(ERR,
                    VROUTER,
                    "N3K service_core: Could not disable service %s\n",
                    service_core->name);
            return -ENOEXEC;
        }

        ret = rte_service_lcore_stop(service_core->mapped_lcore_id);
        if (ret) {
            RTE_LOG(ERR,
                    VROUTER,
                    "N3K service_core: Could not stop service core %u \n",
                    service_core->mapped_lcore_id);
            return -ENOEXEC;
        }

        ret = rte_service_lcore_del(service_core->mapped_lcore_id);
        if (ret) {
            RTE_LOG(ERR,
                    VROUTER,
                    "N3K service_core: Could not delete service core %u \n",
                    service_core->mapped_lcore_id);
            return -ENOEXEC;
        }
    }

    return 0;
}

int
vr_dpdk_n3k_service_core_launch(void)
{
    if (!vr_dpdk_n3k_config_is_n3k_enabled()) {
        return 0;
    }

    FOREACH_ENABLED_N3K_SERVICE_CORE(i, service_core) {
        int ret = rte_service_lcore_add(service_core->mapped_lcore_id);
        if (ret || service_core->mapped_lcore_id < 0) {
            RTE_LOG(ERR,
                    VROUTER,
                    "N3K service_core: Could not add service %s mapped at "
                    "lcore %d\n",
                    service_core->name,
                    service_core->mapped_lcore_id);
            return ret;
        }

        ret = rte_service_lcore_start(service_core->mapped_lcore_id);
        if (ret) {
            RTE_LOG(ERR,
                    VROUTER,
                    "N3K service_core: Could not start service core %s; mapped "
                    "lcore: %u \n",
                    service_core->name,
                    service_core->mapped_lcore_id);
            return -ENOEXEC;
        }

        ret = rte_service_map_lcore_set(
          service_core->service_id, service_core->mapped_lcore_id, 1);
        if (ret) {
            RTE_LOG(ERR,
                    VROUTER,
                    "N3K service_core: Could not run service %s; mapped lcore: "
                    "%u \n",
                    service_core->name,
                    service_core->mapped_lcore_id);
            return -ENOEXEC;
        }

        ret = rte_service_runstate_set(service_core->service_id, 1);
        if (ret) {
            RTE_LOG(
              ERR,
              VROUTER,
              "N3K service_core: Could not set service runstate %s id: %u \n",
              service_core->name,
              service_core->service_id);
            return -ENOEXEC;
        }
    }

    return 0;
}
