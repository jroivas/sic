#!/bin/bash
# Compatibility alias for the current test suite. Forwards to compiletest_rust.sh.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)
exec "${SCRIPT_DIR}/../compiletest_rust.sh" "$@"
