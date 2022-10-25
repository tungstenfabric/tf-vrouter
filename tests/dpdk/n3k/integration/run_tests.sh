#!/bin/bash

set -exuo pipefail

binaries_path="build/debug/vrouter/tests/dpdk/n3k/integration"

test_args=(
    --iova-mode va
    --no-huge
    -m 2048
    --no-pci
    --no-shconf
    --log-level lib.eal:debug
)
for integration_test in $(find $binaries_path -name *_tests -o -name test_* -executable)
do
    CMOCKA_MESSAGE_OUTPUT=STDOUT $integration_test "${test_args[@]}"
done
