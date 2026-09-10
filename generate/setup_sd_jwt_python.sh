#!/usr/bin/env bash
# Clone sd-jwt-python at a pinned revision, apply sd_jwt_python.patch, and
# build it, so the interop tool locks reference implementation (see SD_JWT_PY_REV below)
# from which test vectors are generated from.
#
# Warning: this script resets tracked files in <target-dir> on each invocation.
#
# Usage: ./setup_sd_jwt_python.sh <target-dir>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCH_FILE="$SCRIPT_DIR/sd_jwt_python.patch"
PATH_FILE="$SCRIPT_DIR/.sd-jwt-py-path"

REPO_URL="${SD_JWT_PY_REPO_URL:-https://github.com/openwallet-foundation-labs/sd-jwt-python.git}"
SD_JWT_PY_REV="${SD_JWT_PY_REV:-c5fda017d15e65a6c61a31e696bcdbdab2966b1e}" # Aug 17 2026

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <target-dir>" >&2
    exit 1
fi

if ! command -v poetry >/dev/null 2>&1; then
    echo "ERROR: poetry is required but not found on PATH." >&2
    exit 1
fi

TARGET_DIR="$1"
mkdir -p "$(dirname "$TARGET_DIR")"

if [[ -d "$TARGET_DIR/.git" ]]; then
    echo "Reusing existing clone at '$TARGET_DIR'."
    git -C "$TARGET_DIR" fetch --quiet origin
elif [[ -e "$TARGET_DIR" ]]; then
    echo "ERROR: '$TARGET_DIR' exists and is not a git clone. Refusing to touch it." >&2
    exit 1
else
    git clone --quiet "$REPO_URL" "$TARGET_DIR"
fi

TARGET_DIR="$(cd "$TARGET_DIR" && pwd)"

CURRENT_REV="$(git -C "$TARGET_DIR" rev-parse HEAD)"
if [[ "$CURRENT_REV" != "$SD_JWT_PY_REV" ]]; then
    if [[ -n "$(git -C "$TARGET_DIR" status --porcelain)" ]]; then
        echo "ERROR: '$TARGET_DIR' has uncommitted changes. Refusing to check out over them." >&2
        exit 1
    fi
    git -C "$TARGET_DIR" checkout --quiet "$SD_JWT_PY_REV"
    echo "Checked out sd-jwt-python @ $SD_JWT_PY_REV"
else
    echo "Already at sd-jwt-python @ $SD_JWT_PY_REV"
fi

git -C "$TARGET_DIR" checkout --quiet -- .
if git -C "$TARGET_DIR" apply "$PATCH_FILE"; then
    echo "Applied sd_jwt_python.patch."
else
    echo "ERROR: sd_jwt_python.patch does not apply to $SD_JWT_PY_REV." >&2
    echo "The pin may need to be updated (see comment near SD_JWT_PY_REV)." >&2
    exit 1
fi

(cd "$TARGET_DIR" && poetry install && poetry build)

(cd "$TARGET_DIR/tests/testcases" && poetry run ../../src/sd_jwt/bin/generate.py testcase)
(cd "$TARGET_DIR/examples" && poetry run ../src/sd_jwt/bin/generate.py testcase)
echo "Generated test case and example artifacts."

echo "$TARGET_DIR" > "$PATH_FILE"
echo "Wrote '$TARGET_DIR' to $PATH_FILE"
