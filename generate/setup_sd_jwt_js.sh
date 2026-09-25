#!/usr/bin/env bash
# Build sd-jwt-js interop fixtures: copies the specification.yml/settings.yml
# fixtures already checked out by setup_sd_jwt_python.sh (they're
# implementation-agnostic YAML, not sd-jwt-python code) into <target-dir>,
# then runs generate/js/generate.mjs over them to fill in the artifacts
# (issuer/holder keys, salts, issuance, verified claims) using sd-jwt-js as
# the reference implementation.
#
# Warning: this script overwrites <target-dir> on each invocation.
#
# Usage: ./setup_sd_jwt_js.sh <target-dir>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JS_DIR="$SCRIPT_DIR/js"
PY_PATH_FILE="$SCRIPT_DIR/.sd-jwt-py-path"
JS_PATH_FILE="$SCRIPT_DIR/.sd-jwt-js-path"

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target-dir>" >&2
    exit 1
fi

if [[ ! -f "$PY_PATH_FILE" ]]; then
    echo "ERROR: $PY_PATH_FILE not found. Run setup_sd_jwt_python.sh first (it supplies the" >&2
    echo "specification.yml/settings.yml fixtures this script copies)." >&2
    exit 1
fi
SD_JWT_PY="$(cat "$PY_PATH_FILE")"

if ! command -v node >/dev/null 2>&1; then
    echo "ERROR: node is required but not found on PATH." >&2
    exit 1
fi

TARGET_DIR="$1"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"

for cases_dir in examples tests/testcases; do
    src="$SD_JWT_PY/$cases_dir"
    dst="$TARGET_DIR/$cases_dir"
    mkdir -p "$dst"
    cp "$src/settings.yml" "$dst/settings.yml"
    for case_dir in "$src"/*/; do
        name="$(basename "$case_dir")"
        mkdir -p "$dst/$name"
        cp "$case_dir/specification.yml" "$dst/$name/"
    done
done

TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

(cd "$JS_DIR" && npm install)

case_dirs=()
for cases_dir in examples tests/testcases; do
    for case_dir in "$TARGET_DIR/$cases_dir"/*/; do
        [[ -d "$case_dir" ]] || continue
        case_dirs+=("${case_dir%/}")
    done
done

node "$JS_DIR/generate.mjs" "${case_dirs[@]}"

echo "$TARGET_DIR" > "$JS_PATH_FILE"
echo "Wrote '$TARGET_DIR' to $JS_PATH_FILE"
