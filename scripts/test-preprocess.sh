#!/bin/bash

set -eu

CPP=${CPP:-cpp}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

tests=0
success=0
while read test; do
    tests=$((tests+1))
    if [ -e "${test}.res" ]; then
        if diff -q <("${CPP}" "${test}"|grep -v "^#"|grep -v "^$") "${test}.res" > /dev/null; then
            success=$((success+1))
        else
            echo "*** FAILED ${test}"
        fi
    else
        # Expect it to fail if .res file not found
        if "${CPP}" "${test}" > /dev/null 2>&1; then
            echo "*** FAILED ${test}"
        else
            success=$((success+1))
        fi
    fi
done <<<$(ls "${SCRIPT_DIR}/../tests/preprocess"*.sic)

failed=$((tests-success))
echo "*** Passed ${success}/${tests} (failed ${failed})"
