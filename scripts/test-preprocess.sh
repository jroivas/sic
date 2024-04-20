#!/bin/bash

set -eu

CPP=${CPP:-cpp}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

tests=0
success=0
while read test; do
    tests=$((tests+1))
    if diff -q <("${CPP}" "${test}"|grep -v "^#"|grep -v "^$") "${test}.res"; then
        success=$((success+1))
    else
        echo "*** FAILED ${test}"
    fi
done <<<$(ls "${SCRIPT_DIR}/../tests/preprocess"*.sic)

failed=$((tests-success))
echo "*** Passed ${success}/${tests} (failed ${failed})"
