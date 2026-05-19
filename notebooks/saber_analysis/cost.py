# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Cost computation utilities for SABER eval analysis.

Uses inspect_ai's typed log API (``read_eval_log``) for header-only reads.
"""

from __future__ import annotations

import os

import pandas as pd
from inspect_ai.log import read_eval_log
from inspect_ai.model._model_output import ModelUsage


def calc_cost(usage: ModelUsage, pricing: dict) -> float:
    """Compute dollar cost from a ModelUsage object and per-million-token pricing."""
    inp = usage.input_tokens or 0
    out = usage.output_tokens or 0
    cr = usage.input_tokens_cache_read or 0
    cw = usage.input_tokens_cache_write or 0
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

        log = read_eval_log(log_path, header_only=True)

        # Extract saber_overall score from header
        score = None
        if log.results and log.results.scores:
            for sc in log.results.scores:
                if sc.name == "saber_overall":
                    score = sc.metrics["mean"].value

        # Extract model usage from stats
        agent_cost = 0.0
        agent_usage: ModelUsage | None = None
        if log.stats and log.stats.model_usage:
            for api_model, usage in log.stats.model_usage.items():
                p = pricing.get(api_model)
                if p is None:
                    continue
                agent_cost = calc_cost(usage, p)
                agent_usage = usage

        rows.append(
            {
                "model": model_name,
                "score": score,
                "input_tokens": agent_usage.input_tokens if agent_usage else 0,
                "output_tokens": agent_usage.output_tokens if agent_usage else 0,
                "cache_read": (agent_usage.input_tokens_cache_read or 0) if agent_usage else 0,
                "cache_write": (agent_usage.input_tokens_cache_write or 0) if agent_usage else 0,
                "reasoning_tokens": (agent_usage.reasoning_tokens or 0) if agent_usage else 0,
                "total_tokens": agent_usage.total_tokens if agent_usage else 0,
                "total_cost": agent_cost,
                "cost_per_sample": agent_cost / n_samples if n_samples > 0 else 0,
            }
        )
    return rows
