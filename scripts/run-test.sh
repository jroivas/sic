#!/bin/bash

set -e
set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

. "${SCRIPT_DIR}/build_bin.sh"

RESFILE="${FNAME}.res"

expected_res=0
if [ -f "${RESFILE}" ]; then
    expected_res=$(cat "${RESFILE}")
fi

res=0
"${OUT_DIR}/${BFNAME}.bin" || res=$?

if [ "${res}" -eq "${expected_res}" ]; then
    echo "+++ Success, return $res"
else
    echo "FAILED, return $res"
    exit 1
fi
