#!/bin/sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <version>" >&2
    exit 1
fi

VERSION="$1"

case "$VERSION" in
    ''|*[!0-9.]*|*.*.*.*|*..*|.*|*.)
        echo "Error: version must be in the form X.Y.Z" >&2
        exit 1
        ;;
esac

VERSION="$VERSION" ROOT_DIR="$ROOT_DIR" python3 <<'PY'
import os
import re
from pathlib import Path

root = Path(os.environ["ROOT_DIR"])
version = os.environ["VERSION"]

(root / "VERSION").write_text(f"{version}\n", encoding="utf-8")

library_path = root / "library.json"
library_text = library_path.read_text(encoding="utf-8")
library_text, library_count = re.subn(r'^(\s*"version":\s*")[^"]+(",?)$', rf'\g<1>{version}\2', library_text, count=1, flags=re.MULTILINE)
if library_count != 1:
    raise SystemExit("Could not update version in library.json")
library_path.write_text(library_text, encoding="utf-8")

idf_path = root / "idf_component.yml"
idf_text = idf_path.read_text(encoding="utf-8")
idf_text, idf_count = re.subn(r'^(version:\s*")[^"]+(")$', rf'\g<1>{version}\2', idf_text, count=1, flags=re.MULTILINE)
if idf_count != 1:
    raise SystemExit("Could not update version in idf_component.yml")
idf_path.write_text(idf_text, encoding="utf-8")
PY

echo "Updated release version to $VERSION"
