#!/usr/bin/env bash
# Run the interop tool against every sd-jwt-js example/testcase dir.
# Requires: setup_sd_jwt_js.sh has been run (for .sd-jwt-js-path and generated artifacts) and
# `cargo build` has produced target/debug/sd-jwt-generate.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATH_FILE="$SCRIPT_DIR/.sd-jwt-js-path"
BIN="$SCRIPT_DIR/target/debug/sd-jwt-generate"

if [[ ! -f "$PATH_FILE" ]]; then
    echo "ERROR: $PATH_FILE not found. Run setup_sd_jwt_js.sh first." >&2
    exit 1
fi

if [[ ! -x "$BIN" ]]; then
    echo "ERROR: $BIN not found. Run 'cargo build' in $SCRIPT_DIR first." >&2
    exit 1
fi

sd_jwt_js="$(cat "$PATH_FILE")"

for cases_dir in "$sd_jwt_js/examples" "$sd_jwt_js/tests/testcases"; do
    for test_case_dir in "$cases_dir"/*/; do
        [[ -d "$test_case_dir" ]] || continue
        "$BIN" --reference js -p "${test_case_dir%/}"
    done
done
