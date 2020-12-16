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

#include <cmocka.h>

struct rte_hash;
struct rte_hash_parameters;

extern __attribute__((weak))
    struct rte_hash* rte_hash_create(const struct rte_hash_parameters *params);

extern __attribute__((weak))
    void rte_hash_free(struct rte_hash *h);

extern __attribute__((weak))
    void rte_hash_reset(struct rte_hash *h);

extern __attribute__((weak))
    int32_t rte_hash_add_key_data(const struct rte_hash *h, const void *key, void *data);

extern __attribute__((weak))
    int32_t rte_hash_del_key(const struct rte_hash *h, const void *key);

extern __attribute__((weak))
    int rte_hash_lookup_data(const struct rte_hash *h, const void *key, void **data);

struct rte_hash*
rte_hash_create(const struct rte_hash_parameters *params)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return NULL;
}

void
rte_hash_free(struct rte_hash *h)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
}

void
rte_hash_reset(struct rte_hash *h)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
}

int32_t
rte_hash_add_key_data(const struct rte_hash *h, const void *key, void *data)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int32_t
rte_hash_del_key(const struct rte_hash *h, const void *key)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}

int
rte_hash_lookup_data(const struct rte_hash *h, const void *key, void **data)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}
