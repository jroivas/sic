#!/bin/bash

set -e
set -u

CC=${CC:-cc}
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

. "${SCRIPT_DIR}/build.sh"

"${CC}" "${OUT_DIR}/${BFNAME}.o" -o "${OUT_DIR}/${BFNAME}.bin" -lm
