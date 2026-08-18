#!/usr/bin/env bash
# Refresh the vendored PyPI wheels for the cybench sandbox image.
#
# The cybench sandbox (Dockerfile.sandbox) installs these packages from PyPI so
# builds always pick up the latest versions, and uses docker/wheels/ only as a
# FALLBACK when files.pythonhosted.org is blocked to Docker container traffic
# (the host can still reach PyPI). The wheels are NOT committed — run this on
# such a host before building to populate them.
#
# Wheels must be linux x86_64 / py3.11-compatible (pycryptodome ships an abi3 wheel;
# the rest are pure-python), matching the saber/sandbox:latest base image.
set -euo pipefail

WHEELS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/wheels"
mkdir -p "$WHEELS_DIR"
rm -f "$WHEELS_DIR"/*.whl

python3 -m pip download --only-binary=:all: -d "$WHEELS_DIR" \
    beautifulsoup4 \
    urllib3 \
    pycryptodome

echo "Refreshed wheels in $WHEELS_DIR:"
ls -1 "$WHEELS_DIR"
