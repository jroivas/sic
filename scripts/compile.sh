#!/bin/bash

set -e
set -u

if [ -z ${FNAME+x} ]; then
    if [ $# -lt 1 ]; then
        echo "Missing FNAME variable or file name as parameter"
        exit 1
    fi
    FNAME=${1}
fi

if [ ! -f "${FNAME}" ]; then
    echo "Can't find ${FNAME}"
    exit 1
fi

PWD=$(pwd)
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
OUT_DIR="${PWD}/output"

SIC=${SIC:-${PWD}/sic}
if [ ! -e "${SIC}" ]; then
    echo "Could not find 'sic' compiler at ${SIC}"
    exit 1
fi

BFNAME=$(basename "${FNAME}")
mkdir -p "${OUT_DIR}"

DUMP_TREE=${DUMP_TREE:-0}
DUMP_IR=${DUMP_IR:-0}

EXTRA=""
if [ "${DUMP_TREE}" -eq 1 ]; then
    EXTRA="${EXTRA}--dump-tree"
fi
if [ "${DUMP_IR}" -eq 1 ]; then
    EXTRA="${EXTRA} --dump-ir"
fi

if [ "${VERBOSE:-0}" -eq 1 ]; then
    echo "${SIC} ${FNAME} -o ${OUT_DIR}/${BFNAME}.bc ${EXTRA}"
fi
"${SIC}" "${FNAME}" -o "${OUT_DIR}/${BFNAME}.bc" ${EXTRA}
