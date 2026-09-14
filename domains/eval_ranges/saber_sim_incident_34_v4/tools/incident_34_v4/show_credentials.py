#!/usr/bin/env python3
"""Show the credential inventory for a given RNG seed.

Usage:
    python show_credentials.py 42
    python show_credentials.py --seed 42

Generates the same credentials that init-seed would produce when
SABER_RNG_SEED is set to the given value, without connecting to
any services.
"""
import argparse
import json
import sys
from pathlib import Path

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Show credentials for a given RNG seed"
    )
    parser.add_argument("seed", nargs="?", type=int, help="RNG seed integer")
    parser.add_argument("--seed", dest="seed_flag", type=int, help="RNG seed integer")
    args = parser.parse_args()

    seed_int = args.seed or args.seed_flag
    if seed_int is None:
        parser.error("Please provide an RNG seed: show_credentials.py 42")

    # Find the seeder — works from both export bundle and installed domain
    scenario = "incident_34_v4"
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "docker" / scenario / "init-seed",                        # export bundle
        script_dir.parent.parent / "docker" / "scenarios" / scenario / "init-seed",  # installed (tools/<scenario>/)
    ]
    seeder_dir = None
    for c in candidates:
        if (c / "seeder.py").exists():
            seeder_dir = c
            break
    if seeder_dir is None:
        print(f"ERROR: Could not find seeder.py for {scenario}", file=sys.stderr)
        print(f"  Searched: {', '.join(str(c) for c in candidates)}", file=sys.stderr)
        sys.exit(1)

    # Add seeder dir to path so imports work
    sys.path.insert(0, str(seeder_dir))

    # Patch RNG
    from rng_patch import patch_rng
    patch_rng(seed_int)

    # Mock azure.storage.blob if not installed (only needed for SAS
    # token generation — produces a placeholder instead)
    try:
        import azure.storage.blob
    except ImportError:
        import types
        azure_mod = types.ModuleType("azure")
        azure_storage = types.ModuleType("azure.storage")
        azure_blob = types.ModuleType("azure.storage.blob")
        azure_blob.AccountSasPermissions = type("AccountSasPermissions", (), {"__init__": lambda self, **kw: None})
        azure_blob.ResourceTypes = type("ResourceTypes", (), {"__init__": lambda self, **kw: None})
        azure_blob.generate_account_sas = lambda **kw: "MOCK_SAS_TOKEN_install_azure_storage_blob_for_real_values"
        azure_mod.storage = azure_storage
        azure_storage.blob = azure_blob
        sys.modules["azure"] = azure_mod
        sys.modules["azure.storage"] = azure_storage
        sys.modules["azure.storage.blob"] = azure_blob

    # Import and run the value generator from seeder
    import importlib.util
    spec = importlib.util.spec_from_file_location("seeder", seeder_dir / "seeder.py")
    seeder = importlib.util.module_from_spec(spec)

    # We need yaml for the seeder
    try:
        import yaml
    except ImportError:
        print("ERROR: pyyaml required. Install with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)

    spec.loader.exec_module(seeder)

    # Load template and generate values
    template_path = seeder_dir / "seed_manifest.template.yaml"
    if not template_path.exists():
        print(f"ERROR: {template_path} not found", file=sys.stderr)
        sys.exit(1)

    import yaml
    with open(template_path) as f:
        template = yaml.safe_load(f)

    values = seeder.generate_all_values(template)

    print(f"Credential inventory for SABER_RNG_SEED={seed_int}")
    print(f"Scenario: {scenario}")
    print("=" * 60)
    for name, value in sorted(values.items()):
        display = str(value)
        if len(display) > 80:
            display = display[:77] + "..."
        print(f"  {name:30s} {display}")

    # Show attack chain with credential mapping
    creds_candidates = [
        script_dir / "attack_chain.yaml",                                      # installed (tools/<scenario>/)
        script_dir.parent / "attack_chain.yaml",                               # export bundle root
    ]

    creds_path = None
    for c in creds_candidates:
        if c.exists():
            creds_path = c
            break

    if creds_path:
        with open(creds_path) as f:
            creds_data = yaml.safe_load(f)
        chain = creds_data.get("attack_chain", [])
        if chain:
            print()
            print("Attack Chain")
            print("=" * 60)
            for step in chain:
                step_num = step.get("step", "?")
                desc = step.get("description", "")[:70]
                uses = step.get("credential_used", "none")
                gets = step.get("credential_obtained", "none")
                print(f"  Step {step_num}: {desc}")
                if uses and uses != "none":
                    uses_val = str(values.get(uses, "?"))
                    if len(uses_val) > 60:
                        uses_val = uses_val[:57] + "..."
                    print(f"    Uses: {uses} = {uses_val}")
                else:
                    print(f"    Uses: (none)")
                if gets and gets != "none":
                    gets_val = str(values.get(gets, "?"))
                    if len(gets_val) > 60:
                        gets_val = gets_val[:57] + "..."
                    print(f"    Gets: {gets} = {gets_val}")
                else:
                    print(f"    Gets: (none)")
                print()

if __name__ == "__main__":
    main()
