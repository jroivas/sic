#!/bin/bash

set -e
set -u

PWD=$(pwd)
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

tests=0
success=0
while read test; do
    tests=$((tests+1))
    if ! "${SCRIPT_DIR}/run-test.sh" "$test"; then
        continue
    fi
    success=$((success+1))
done <<<$(ls "${PWD}/../tests/"*.sic)

failed=$((tests-success))
echo "*** Passed ${success}/${tests} (failed ${failed})"
