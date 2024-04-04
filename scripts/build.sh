#!/bin/bash

set -e
set -u

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)

. "${SCRIPT_DIR}/compile.sh"

llc -O0 -relocation-model=pic -filetype=obj "${OUT_DIR}/${BFNAME}.bc" -o "${OUT_DIR}/${BFNAME}.o"
