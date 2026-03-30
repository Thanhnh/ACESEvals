"""Shared plot configuration and helpers for SABER analysis notebooks."""

from __future__ import annotations

import re

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt


def setup_plotting() -> None:
    """Apply consistent matplotlib defaults for SABER notebooks."""
    plt.rcParams.update(
        {
            "figure.figsize": (12, 6),
            "font.size": 12,
            "axes.titlesize": 14,
            "axes.labelsize": 12,
            "figure.dpi": 120,
            "axes.grid": True,
            "grid.alpha": 0.3,
        }
    )


def make_legend_patches(
    model_order: list[str],
    colors: dict[str, str],
    include_reasoning_delta: bool = True,
) -> list[mpatches.Patch]:
    """Build a list of legend patches for model colors + optional reasoning delta."""
    handles = [
        mpatches.Patch(facecolor=colors[m], edgecolor="black", alpha=0.85, label=m)
        for m in model_order
        if m in colors
    ]
    if include_reasoning_delta:
        handles.append(
            mpatches.Patch(
                facecolor="gray",
                edgecolor="black",
                alpha=0.45,
                hatch="///",
                label="Δ extended reasoning",
            )
        )
    return handles


def classify_score_type(st: str) -> str:
    """Map raw score_type to display category."""
    if st == "submission":
        return "Submission"
    if st.startswith("checkpoint"):
        return "Checkpoints"
    if st == "aggregate":
        return "Aggregate"
    # Domain-specific checkpoints (e.g. c0_cti_analysis, c4_detection_quality)
    if re.match(r"^c\d+_", st):
        return "Checkpoints"
    return "Other"
