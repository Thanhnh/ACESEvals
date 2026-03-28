"""Cost computation utilities for SABER eval analysis."""

from __future__ import annotations

import json
import os
import zipfile

import pandas as pd


def calc_cost(usage: dict, pricing: dict) -> float:
    """Compute dollar cost from a token-usage dict and per-million-token pricing."""
    inp = usage.get("input_tokens", 0)
    out = usage.get("output_tokens", 0)
    cr = usage.get("input_tokens_cache_read", 0)
    cw = usage.get("input_tokens_cache_write", 0)
    return (
        (inp / 1e6) * pricing["input"]
        + (out / 1e6) * pricing["output"]
        + (cr / 1e6) * pricing["cache_read"]
        + (cw / 1e6) * pricing["cache_write"]
    )


def extract_cost_rows(
    log_dict: dict[str, str],
    log_dir: str,
    pricing: dict[str, dict],
    n_samples: int,
) -> list[dict]:
    """Extract cost and token usage from eval logs.

    Parameters
    ----------
    log_dict : dict
        {display_name: filename.eval}
    log_dir : str
        Directory containing .eval files.
    pricing : dict
        {api_model_id: {input, output, cache_read, cache_write}} in $/1M tokens.
    n_samples : int
        Number of samples (for per-sample cost).
    """
    rows: list[dict] = []
    for model_name, log_file in log_dict.items():
        log_path = os.path.join(log_dir, log_file)
        if not os.path.exists(log_path):
            continue
        with zipfile.ZipFile(log_path) as z:
            header = json.loads(z.read("header.json"))
        mu = header.get("stats", {}).get("model_usage", {})
        score = None
        for s in header.get("results", {}).get("scores", []):
            if s.get("name") == "saber_overall":
                score = s["metrics"]["mean"]["value"]
        agent_cost = 0.0
        agent_tokens: dict = {}
        for api_model, usage in mu.items():
            p = pricing.get(api_model)
            if p is None:
                continue
            agent_cost = calc_cost(usage, p)
            agent_tokens = usage
        rows.append(
            {
                "model": model_name,
                "score": score,
                "input_tokens": agent_tokens.get("input_tokens", 0),
                "output_tokens": agent_tokens.get("output_tokens", 0),
                "cache_read": agent_tokens.get("input_tokens_cache_read", 0),
                "cache_write": agent_tokens.get("input_tokens_cache_write", 0),
                "reasoning_tokens": agent_tokens.get("reasoning_tokens", 0),
                "total_tokens": agent_tokens.get("total_tokens", 0),
                "total_cost": agent_cost,
                "cost_per_sample": agent_cost / n_samples if n_samples > 0 else 0,
            }
        )
    return rows
