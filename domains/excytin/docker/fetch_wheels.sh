#!/usr/bin/env bash
# Refresh the vendored PyPI wheels for the excytin sandbox image.
#
# The excytin sandbox (Dockerfile.sandbox) installs these packages from PyPI so
# builds always pick up the latest versions, and uses docker/wheels/ only as a
# FALLBACK (--no-index --find-links) when container egress to
# files.pythonhosted.org (PyPI's CDN) is blocked. The wheels are NOT committed —
# run this on a host with PyPI access before building to populate them.
#
# Wheels target the base image interpreter: CPython 3.11 / linux x86_64.
set -euo pipefail

WHEELS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wheels"
mkdir -p "$WHEELS_DIR"
rm -f "$WHEELS_DIR"/*.whl

python3 -m pip download \
    --only-binary=:all: \
    --python-version 311 \
    --platform manylinux2014_x86_64 \
    --platform manylinux_2_17_x86_64 \
    -d "$WHEELS_DIR" \
    pymysql \
    sqlalchemy

echo "Refreshed wheels in $WHEELS_DIR:"
ls -1 "$WHEELS_DIR"
