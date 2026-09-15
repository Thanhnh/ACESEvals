#!/usr/bin/env bash
# Refresh the vendored PyPI wheels for the cti_realm images (sandbox,
# kusto-init, mitre-service). All three share this one wheels/ directory.
#
# These wheels are NOT committed (the closure is large — pandas / numpy / azure /
# cryptography, ~40MB). Each image always installs from PyPI first, and falls
# back to these wheels only when container egress to files.pythonhosted.org
# (PyPI's CDN) is blocked. To enable that fallback on a restricted network, run
# this on a host with PyPI access before building:
#
#   domains/cti_realm/docker/fetch_wheels.sh
#
# (Azure CLI installs from packages.microsoft.com, which is reachable from the
# container, so only the PyPI step needs vendoring.)
#
# Wheels target the base image interpreter: CPython 3.11 / linux x86_64.
set -euo pipefail

DOCKER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEELS_DIR="$DOCKER_DIR/wheels"
mkdir -p "$WHEELS_DIR"
rm -f "$WHEELS_DIR"/*.whl

python3 -m pip download \
    --only-binary=:all: \
    --python-version 311 \
    --platform manylinux2014_x86_64 \
    --platform manylinux_2_17_x86_64 \
    -d "$WHEELS_DIR" \
    -r "$DOCKER_DIR/kusto_init/requirements.txt" \
    -r "$DOCKER_DIR/mitre_service/requirements.txt" \
    azure-kusto-data \
    azure-kusto-ingest \
    azure-identity \
    pysigma \
    httpx \
    pyyaml \
    jsonschema \
    pandas \
    stix2

echo "Refreshed wheels in $WHEELS_DIR:"
ls -1 "$WHEELS_DIR"
