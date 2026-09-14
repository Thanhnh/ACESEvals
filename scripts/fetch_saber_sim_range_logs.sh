#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [[ $# -gt 0 ]]; then
    domains=("$@")
else
    domains=(domains/eval_ranges/saber_sim_*)
fi

for domain in "${domains[@]}"; do
    [[ -d "$domain" ]] || { echo "missing domain: $domain" >&2; exit 1; }
    echo "Materializing range logs for ${domain#domains/}"
    "$REPO_ROOT/.venv/bin/python" - "$domain" <<'PY'
import importlib.util
import sys
from pathlib import Path

domain_root = Path(sys.argv[1]).resolve()
spec = importlib.util.spec_from_file_location(f"{domain_root.name}_setup", domain_root / "setup.py")
if spec is None or spec.loader is None:
    raise RuntimeError(f"Unable to load {domain_root / 'setup.py'}")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
hook_type = getattr(module, "MaterializeRangeLogs", None)
if hook_type is None:
    raise RuntimeError(f"{domain_root.name} has no MaterializeRangeLogs hook; re-export the domain")
hook = hook_type()
if hook.should_run(domain_root):
    hook.run(domain_root)
else:
    print("  logs already present")
PY
done