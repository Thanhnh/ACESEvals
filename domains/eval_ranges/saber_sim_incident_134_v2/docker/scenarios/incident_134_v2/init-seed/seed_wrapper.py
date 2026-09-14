#!/usr/bin/env python3
"""Wrapper that optionally seeds RNG before running seeder.py."""
import os
import runpy
from pathlib import Path

rng_seed = os.environ.get("SABER_RNG_SEED", "").strip()
status_dir = Path("/seed-status")
status_dir.mkdir(parents=True, exist_ok=True)
done_marker = status_dir / "init-seed.done"
failed_marker = status_dir / "init-seed.failed"
done_marker.unlink(missing_ok=True)
failed_marker.unlink(missing_ok=True)
if rng_seed:
    try:
        seed_int = int(rng_seed)
        from rng_patch import patch_rng
        print(f"[RNG] Seeding with SABER_RNG_SEED={seed_int}")
        patch_rng(seed_int)
    except ValueError:
        print(f"WARNING: SABER_RNG_SEED={rng_seed!r} is not an integer, ignoring")
try:
    runpy.run_path("seeder.py", run_name="__main__")
except Exception:
    failed_marker.write_text("failed\n")
    raise
done_marker.write_text("completed\n")
