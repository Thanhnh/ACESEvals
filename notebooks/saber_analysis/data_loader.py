"""Generic eval log parsing — works for any SABER domain."""

from __future__ import annotations

import json
import os
import re
import shutil
import zipfile
from typing import Any, Callable

import pandas as pd

# HuggingFace dataset coordinates
HF_REPO_ID = "anandmudgerikar/AcesEvals"
HF_REPO_TYPE = "dataset"
HF_PATH_PREFIX = "latest_experiment_samples"


def ensure_eval_files(
    eval_logs: dict[str, str],
    log_dir: str,
    domain: str,
    baseline_logs: dict[str, str] | None = None,
    fallback_dirs: list[str] | None = None,
) -> None:
    """Ensure all required .eval files exist locally, downloading from HuggingFace if needed.

    Resolution order for each file:

    1. ``log_dir`` — primary local directory (checked first).
    2. ``fallback_dirs`` — additional local directories (e.g. ``latest_experiments/``).
       If found, the file is **copied** into *log_dir* so subsequent runs are fast.
    3. **HuggingFace** — downloaded from the AcesEvals dataset as a last resort.

    Args:
        eval_logs: Mapping of display name → .eval filename.
        log_dir: Local directory where .eval files should live.
        domain: Domain subfolder on HuggingFace (e.g. ``"excytin"``, ``"cybench"``).
        baseline_logs: Optional mapping of display name → baseline .eval filename.
        fallback_dirs: Extra local directories to search before downloading from HF.
    """
    all_filenames: set[str] = set(eval_logs.values())
    if baseline_logs:
        all_filenames.update(baseline_logs.values())

    missing = [
        fname
        for fname in sorted(all_filenames)
        if not os.path.exists(os.path.join(log_dir, fname))
    ]

    if not missing:
        print(f"✓ All {len(all_filenames)} eval files found locally in {log_dir}")
        return

    # Try to resolve from fallback local directories first
    os.makedirs(log_dir, exist_ok=True)
    still_missing: list[str] = []
    for fname in missing:
        resolved = False
        for fb_dir in (fallback_dirs or []):
            fb_path = os.path.join(fb_dir, fname)
            if os.path.exists(fb_path):
                dest = os.path.join(log_dir, fname)
                shutil.copy2(fb_path, dest)
                print(f"  ← {fname} (copied from {fb_dir})")
                resolved = True
                break
        if not resolved:
            still_missing.append(fname)

    if not still_missing:
        n_local = len(all_filenames) - len(missing)
        n_fallback = len(missing)
        print(f"✓ All {len(all_filenames)} eval files ready in {log_dir} "
              f"({n_local} local, {n_fallback} from fallback dirs)")
        return

    n_found = len(all_filenames) - len(still_missing)
    print(f"  {n_found}/{len(all_filenames)} eval files found locally")
    print(f"  Downloading {len(still_missing)} missing file(s) from HuggingFace …")

    from huggingface_hub import hf_hub_download

    for idx, filename in enumerate(still_missing, 1):
        hf_path = f"{HF_PATH_PREFIX}/{domain}/{filename}"
        print(f"    [{idx}/{len(still_missing)}] ↓ {filename} …")
        cached = hf_hub_download(
            repo_id=HF_REPO_ID,
            filename=hf_path,
            repo_type=HF_REPO_TYPE,
        )
        dest = os.path.join(log_dir, filename)
        shutil.copy2(cached, dest)
        size_mb = os.path.getsize(dest) / (1024 * 1024)
        print(f"           ✓ {size_mb:.1f} MB")

    print(f"✓ All {len(all_filenames)} eval files ready in {log_dir}")


def _default_group_extractor(sample_id: str) -> str:
    """Default: no grouping — returns a single group for all samples."""
    return "all"


def _parse_score_type(score_key: str) -> str:
    """Classify a score key into submission / checkpoint_N / aggregate / other."""
    if ".submission" in score_key:
        return "submission"
    if ".checkpoint_" in score_key:
        m = re.search(r"\.checkpoint_(\d+)$", score_key)
        return f"checkpoint_{m.group(1)}" if m else "checkpoint"
    if ".aggregate" in score_key:
        return "aggregate"
    return "other"


def _load_single_eval(
    path: str,
    model_name: str,
    group_fn: Callable[[str], str],
) -> tuple[dict[str, Any] | None, list[dict], list[dict]]:
    """Parse one .eval ZIP file. Returns (overall_dict, sample_rows, subtask_rows)."""
    overall = None
    samples: list[dict] = []
    subtasks: list[dict] = []

    with zipfile.ZipFile(path) as z:
        header = json.loads(z.read("header.json"))
        status = header.get("status")
        if status != "success":
            print(f"⚠ {os.path.basename(path)}: status={status} — skipping")
            return None, [], []

        for sc in header.get("results", {}).get("scores", []):
            if sc.get("name") == "saber_overall":
                overall = {
                    "mean": sc["metrics"]["mean"]["value"],
                    "stderr": sc["metrics"]["stderr"]["value"],
                }

        for name in z.namelist():
            if not (name.startswith("samples/") and name.endswith(".json")):
                continue
            sample = json.loads(z.read(name))
            sample_id = sample.get("id", "")
            group = group_fn(sample_id)
            scores = sample.get("scores", {})

            overall_val = scores.get("saber_overall", {}).get("value")
            if overall_val is not None:
                samples.append(
                    {
                        "model": model_name,
                        "sample_id": sample_id,
                        "group": group,
                        "score": float(overall_val),
                    }
                )

            for score_key, score_obj in scores.items():
                if score_key == "saber_overall":
                    continue
                val = score_obj.get("value")
                if val is None:
                    continue
                subtasks.append(
                    {
                        "model": model_name,
                        "sample_id": sample_id,
                        "group": group,
                        "score_type": _parse_score_type(score_key),
                        "score": float(val),
                    }
                )

    return overall, samples, subtasks


def load_eval_logs(
    eval_logs: dict[str, str],
    log_dir: str,
    model_order: list[str],
    group_fn: Callable[[str], str] | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    """Load primary eval logs.

    Parameters
    ----------
    eval_logs : dict
        Mapping of display name → .eval filename.
    log_dir : str
        Directory containing the .eval files.
    model_order : list
        Ordered list of model display names.
    group_fn : callable, optional
        Function that takes a sample_id string and returns a group label.
        If None, all samples are assigned to group ``"all"``.

    Returns
    -------
    samples_df : DataFrame
        Per-sample saber_overall scores with columns [model, sample_id, group, score].
    subtasks_df : DataFrame
        Per-subtask scores with columns [model, sample_id, group, score_type, score].
    overall_df : DataFrame
        Mean/stderr per model (indexed by model name).
    model_overall : dict
        Raw {model_name: {mean, stderr}} dict.
    """
    if group_fn is None:
        group_fn = _default_group_extractor

    all_samples: list[dict] = []
    all_subtasks: list[dict] = []
    model_overall: dict[str, dict] = {}

    for model_name, log_file in eval_logs.items():
        path = os.path.join(log_dir, log_file)
        if not os.path.exists(path):
            print(f"⚠ Missing: {path} — skipping {model_name}")
            continue
        overall, samples, subtasks = _load_single_eval(path, model_name, group_fn)
        if overall is not None:
            model_overall[model_name] = overall
        all_samples.extend(samples)
        all_subtasks.extend(subtasks)

    samples_df = pd.DataFrame(all_samples)
    subtasks_df = pd.DataFrame(all_subtasks)
    overall_df = pd.DataFrame(model_overall).T.reindex(model_order)

    return samples_df, subtasks_df, overall_df, model_overall


def load_baseline_logs(
    baseline_logs: dict[str, str],
    log_dir: str,
    group_fn: Callable[[str], str] | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Load baseline (no-reasoning) eval logs.

    Returns
    -------
    baseline_samples_df, baseline_subtasks_df, no_thinking_overall
    """
    if group_fn is None:
        group_fn = _default_group_extractor

    all_samples: list[dict] = []
    all_subtasks: list[dict] = []
    no_thinking_overall: dict[str, dict] = {}

    for model_name, log_file in baseline_logs.items():
        path = os.path.join(log_dir, log_file)
        if not os.path.exists(path):
            print(f"⚠ Missing baseline: {path} — skipping")
            continue
        overall, samples, subtasks = _load_single_eval(path, model_name, group_fn)
        if overall is not None:
            no_thinking_overall[model_name] = overall
        all_samples.extend(samples)
        all_subtasks.extend(subtasks)

    return pd.DataFrame(all_samples), pd.DataFrame(all_subtasks), no_thinking_overall
