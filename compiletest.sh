#!/usr/bin/env bash
# Compatibility alias for the current test suite. Forwards to compiletest_rust.sh.
MYDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
exec "$MYDIR/compiletest_rust.sh" "$@"
