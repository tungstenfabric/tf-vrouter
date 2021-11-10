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

extern void * __attribute__((weak))
    rte_zmalloc(const char *type, size_t size, unsigned align);
extern void __attribute__((weak)) rte_free(void *ptr);
extern void __attribute__((weak)) rte_free(void *ptr);

extern int __attribute__((weak))
    rte_log(uint32_t level, uint32_t logtype, const char *format, ...);

int __thread per_lcore__rte_errno __attribute__((weak));

void *
rte_zmalloc(const char *type, size_t size, unsigned align)
{
    ((void)type);
    ((void)align);

    uint8_t *memory = test_malloc(size);
    if (memory != NULL) {
        memset(memory, 0, size);
    }

    return memory;
}

void
rte_free(void *ptr)
{
    if (ptr != NULL) {
        test_free(ptr);
    }
}

int
rte_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    fail_msg("Weak version of %s(); should not be called because of mocking", __func__);
    return 0;
}
