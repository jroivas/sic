#!/usr/bin/env bash

set -eu

usage() {
    echo "Usage: $0 build_folder [llvm] [--env VENV_DIR]"
    echo ""
    echo "  build_folder   Directory to write generated IR and binaries"
    echo "  llvm           Also assemble, link, run and verify exit code"
    echo "  --env VENV_DIR Python venv to use (default: auto-detect .env2/.env)"
    echo ""
    echo "  Env overrides: PYTHON, SIC, HOSTCC, CC"
    exit 1
}

MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
TESTDIR="$MYDIR/tests"

if [ $# -lt 1 ]; then
    usage
fi

outfolder=$1
shift
llvm=0
venv_arg=""

while [ $# -gt 0 ]; do
    case "$1" in
        llvm)       llvm=1 ;;
        --env)      shift; venv_arg="$1" ;;
        --env=*)    venv_arg="${1#--env=}" ;;
        -h|--help)  usage ;;
        *)          echo "Unknown argument: $1"; usage ;;
    esac
    shift
done

# Activate venv: explicit --env > auto-detect > already-set PYTHON
if [ -z "${PYTHON:-}" ]; then
    if [ -n "$venv_arg" ]; then
        # shellcheck source=/dev/null
        source "$venv_arg/bin/activate"
    else
        for venv in "$MYDIR/.env2" "$MYDIR/.env"; do
            if [ -f "$venv/bin/activate" ]; then
                # shellcheck source=/dev/null
                source "$venv/bin/activate"
                break
            fi
        done
    fi
    PYTHON="${VIRTUAL_ENV:+$VIRTUAL_ENV/bin/python}"
fi

# Fall back to PATH search
if [ -z "${PYTHON:-}" ]; then
    PYTHON="$(command -v python3 || command -v python)"
fi

SIC="${SIC:-$PYTHON $MYDIR/sic.py}"
HOSTCC="${HOSTCC:-${CC:-cc}}"

mkdir -p "$outfolder"

tests=0
success=0

dotest() {
    local test="$1"
    local base
    base=$(basename "$test" .sic)
    echo "*** $base"
    tests=$((tests + 1))

    local ir_file="$outfolder/$base.sic.ir"

    if ! $SIC -S "$test" -o "$ir_file" 2>&1; then
        echo "FAILED: sic compile"
        return 1
    fi

    if [ "$llvm" -eq 1 ]; then
        local bc_file="$ir_file.bc"
        local obj_file="$outfolder/$base.ir.o"
        local bin_file="$outfolder/$base.ir.bin"

        if ! llvm-as "$ir_file" -o "$bc_file" 2>&1; then
            echo "FAILED: llvm-as"
            return 1
        fi
        if ! llc -O0 -relocation-model=pic -filetype=obj "$bc_file" -o "$obj_file" 2>&1; then
            echo "FAILED: llc"
            return 1
        fi
        if ! $HOSTCC "$obj_file" -o "$bin_file" -lm 2>&1; then
            echo "FAILED: link"
            return 1
        fi

        local expected_res=0
        if [ -f "$test.res" ]; then
            expected_res=$(cat "$test.res")
        fi

        set +e
        "$bin_file"
        local res=$?
        set -e

        if [ "${res}" -eq "${expected_res}" ]; then
            echo "+++ Success, return $res"
        else
            echo "FAILED: expected exit $expected_res, got $res"
            return 1
        fi
    fi
    return 0
}

while IFS= read -r test; do
    if dotest "$test"; then
        success=$((success + 1))
    fi
done < <(ls "$TESTDIR"/test_*.sic)

failed=$((tests - success))
echo ""
echo "*** Passed ${success}/${tests} (failed ${failed})"
