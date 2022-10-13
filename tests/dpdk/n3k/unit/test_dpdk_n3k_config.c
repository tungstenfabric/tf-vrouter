
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>

#include <errno.h>
#include <getopt.h>

#include <vr_dpdk.h>
#include <vr_dpdk_n3k_config.h>

#include <cmocka.h>


#define GROUP_NAME "vr_dpdk_n3k_config"

static int test_teardown(void **state) {
    /* Resets option index of Getopt component */
    optind = 1;
    return 0;
}

static void
test_dpdk_n3k_config_is_n3k_disabled(void **state)
{
    /* GIVEN no arguments */

    /* WHEN just after start */

    /* THEN internal state matches the values */
    const char *ptrName;
    assert_false(vr_dpdk_n3k_config_is_n3k_enabled());

    ptrName = vr_dpdk_n3k_config_get_phy_repr_name(NULL);
    assert_int_equal(strlen(ptrName), 0);
}

static void
test_dpdk_n3k_config_representor_name(void **state)
{
    /* GIVEN cli arguments */
    char *refName = "net_bonding0";
    char *argvals[] = {"--enable_n3k", refName};
    const char *ptrName;

    /* WHEN cli arguments are parsed*/
    vr_dpdk_n3k_config_parse_opt(2, argvals, 0);

    /* THEN internal state matches the values */
    assert_true(vr_dpdk_n3k_config_is_n3k_enabled());

    ptrName = vr_dpdk_n3k_config_get_phy_repr_name(NULL);
    assert_memory_equal(ptrName, refName, strlen(refName));
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_dpdk_n3k_config_is_n3k_disabled),
        cmocka_unit_test_teardown(test_dpdk_n3k_config_representor_name, test_teardown)
    };

    return cmocka_run_group_tests_name(GROUP_NAME, tests, NULL, NULL);
}
