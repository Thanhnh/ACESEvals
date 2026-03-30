"""Generic eval log parsing — works for any SABER domain.

Uses inspect_ai's typed log API where possible:
- ``read_eval_log(header_only=True)`` for run-level results/stats
- ``read_eval_log_sample_summaries`` for per-sample scores and timing
- ``read_eval_log_sample`` for per-sample message/tool-call detail

Falls back to raw ZIP/JSON for individual samples that fail typed
deserialization (event schema drift across inspect_ai versions).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import zipfile
from typing import Any, Callable

import pandas as pd
from inspect_ai.log import (
    read_eval_log,
    read_eval_log_sample,
    read_eval_log_sample_summaries,
)
from inspect_ai.model._chat_message import ChatMessageAssistant

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
    """Classify a score key into submission / checkpoint_N / aggregate / or the raw key.

    Handles both old format (task_name.submission) and new format (submission).
    Domain-specific score keys (e.g. CTI Realm's ``c0_cti_analysis``) are preserved
    as-is so domain notebooks can filter on them directly.
    """
    # Strip task prefix if present (e.g. "incident_134_task_10.submission" -> "submission")
    suffix = score_key.rsplit(".", 1)[-1] if "." in score_key else score_key
    if suffix == "submission":
        return "submission"
    m = re.match(r"^checkpoint_(\d+)$", suffix)
    if m:
        return f"checkpoint_{m.group(1)}"
    if suffix == "aggregate":
        return "aggregate"
    # Preserve domain-specific score keys (e.g. c0_cti_analysis, c4_detection_quality)
    return suffix


def _load_single_eval(
    path: str,
    model_name: str,
    group_fn: Callable[[str], str],
) -> tuple[dict[str, Any] | None, list[dict], list[dict]]:
    """Parse one .eval file using inspect_ai's typed API.

    Uses ``read_eval_log`` (header only) for overall scores, and
    ``read_eval_log_sample_summaries`` for per-sample scores — avoids
    full event deserialization which can fail across inspect_ai versions.

    Returns (overall_dict, sample_rows, subtask_rows).
    """
    overall = None
    samples: list[dict] = []
    subtasks: list[dict] = []

    log = read_eval_log(path, header_only=True)
    if log.status != "success":
        print(f"⚠ {os.path.basename(path)}: status={log.status} — skipping")
        return None, [], []

    # Extract saber_overall from header results
    if log.results and log.results.scores:
        for sc in log.results.scores:
            if sc.name == "saber_overall":
                overall = {
                    "mean": sc.metrics["mean"].value,
                    "stderr": sc.metrics["stderr"].value,
                }

    # Use sample summaries — lightweight, no event parsing
    for summary in read_eval_log_sample_summaries(path):
        sample_id = str(summary.id)
        group = group_fn(sample_id)

        if summary.scores:
            overall_score = summary.scores.get("saber_overall")
            if overall_score is not None:
                samples.append(
                    {
                        "model": model_name,
                        "sample_id": sample_id,
                        "group": group,
                        "score": float(overall_score.value),
                    }
                )

            for score_key, score_obj in summary.scores.items():
                if score_key == "saber_overall":
                    continue
                if score_obj.value is None:
                    continue
                subtasks.append(
                    {
                        "model": model_name,
                        "sample_id": sample_id,
                        "group": group,
                        "score_type": _parse_score_type(score_key),
                        "score": float(score_obj.value),
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


def _extract_tool_calls(
    path: str,
    sample_id: str,
) -> tuple[int, int, dict[str, int]]:
    """Load a single sample and extract step/tool call counts.

    Tries inspect_ai's typed API first, falls back to raw ZIP/JSON
    for samples whose events don't deserialize cleanly.

    Returns (n_steps, n_tool_calls, tool_counts).
    """
    # Try typed API first
    try:
        sample = read_eval_log_sample(path, id=sample_id)
        n_steps = 0
        tool_counts: dict[str, int] = {}
        total_tool_calls = 0
        for msg in sample.messages:
            if isinstance(msg, ChatMessageAssistant):
                n_steps += 1
                if msg.tool_calls:
                    for tc in msg.tool_calls:
                        tool_counts[tc.function] = tool_counts.get(tc.function, 0) + 1
                        total_tool_calls += 1
        return n_steps, total_tool_calls, tool_counts
    except Exception:
        pass

    # Fallback: raw JSON for samples with event schema drift
    try:
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not (name.startswith("samples/") and name.endswith(".json")):
                    continue
                raw = json.loads(z.read(name))
                if str(raw.get("id", "")) != sample_id:
                    continue
                n_steps = 0
                tool_counts = {}
                total_tool_calls = 0
                for m in raw.get("messages", []):
                    if m.get("role") == "assistant":
                        n_steps += 1
                        for tc in m.get("tool_calls", []):
                            fn = tc.get("function", "unknown")
                            tool_counts[fn] = tool_counts.get(fn, 0) + 1
                            total_tool_calls += 1
                return n_steps, total_tool_calls, tool_counts
    except Exception:
        pass

    return 0, 0, {}


def load_trajectory_data(
    eval_logs: dict[str, str],
    log_dir: str,
    model_order: list[str],
    group_fn: Callable[[str], str] | None = None,
) -> pd.DataFrame:
    """Extract per-sample trajectory metadata from eval logs.

    Uses ``read_eval_log_sample_summaries`` for scores and timing, then
    ``read_eval_log_sample`` per sample for tool call detail. This avoids
    the full-stream deserialization issues across inspect_ai versions.

    Returns a DataFrame with columns:
    ``[model, sample_id, group, score, n_steps, n_tool_calls, tool_counts,
    total_time, working_time, message_count]``
    """
    if group_fn is None:
        group_fn = _default_group_extractor

    rows: list[dict] = []
    for model_name, log_file in eval_logs.items():
        path = os.path.join(log_dir, log_file)
        if not os.path.exists(path):
            continue

        log = read_eval_log(path, header_only=True)
        if log.status != "success":
            continue

        # Summaries are lightweight and always parse successfully
        summaries = read_eval_log_sample_summaries(path)
        for summary in summaries:
            sample_id = str(summary.id)
            score_obj = summary.scores.get("saber_overall") if summary.scores else None
            score = float(score_obj.value) if score_obj is not None else None

            # Load full sample for tool call detail
            n_steps, n_tool_calls, tool_counts = _extract_tool_calls(path, sample_id)

            rows.append(
                {
                    "model": model_name,
                    "sample_id": sample_id,
                    "group": group_fn(sample_id),
                    "score": score,
                    "n_steps": n_steps,
                    "n_tool_calls": n_tool_calls,
                    "tool_counts": tool_counts,
                    "total_time": summary.total_time,
                    "working_time": summary.working_time,
                    "message_count": summary.message_count,
                }
            )

    df = pd.DataFrame(rows)
    # Enforce model ordering for consistent plotting
    df["model"] = pd.Categorical(df["model"], categories=model_order, ordered=True)
    return df
