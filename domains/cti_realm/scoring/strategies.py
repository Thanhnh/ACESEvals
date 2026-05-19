# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""CTI Realm scoring strategies.

Five checkpoint strategies registered via ``get_strategies()`` in ``__init__.py``.
Each returns a score in ``[0, max_score]`` and ``saber_overall`` aggregates them
using the default weighted-average path: ``Σ(score) / Σ(max_score) = total / 10``.

- **CTIAlignmentStrategy** — C0: CTI report usage + LLM alignment (max 1.25).
- **MITREJaccardStrategy** — C1: MITRE technique Jaccard (max 0.75).
- **DataExplorationStrategy** — C2: Data exploration Jaccard (max 1.0).
- **QueryIterationStrategy** — C3: ≥2 unique successful queries (max 0.5).
- **DetectionQualityStrategy** — C4: KQL F1 + Sigma quality (max 6.5).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from inspect_ai.scorer import Score

from saber.scoring.context import ScoringContext
from saber.scoring.templates import TemplateRenderer

from ._trajectory import (
    detect_cti_usage,
    detect_data_exploration,
    detect_mitre_techniques,
    detect_query_iteration,
    score_cti_alignment,
)
from ._helpers import criteria_dict, criteria_list, criteria_str
from ._kql import score_kql_f1, verify_results_from_tool_steps
from ._parsing import parse_model_output
from ._sigma import score_sigma_rule

logger = logging.getLogger("saber.domains.cti_realm.scoring.strategies")


# ═══════════════════════════════════════════════════════════════════
# Private helpers
# ═══════════════════════════════════════════════════════════════════


def _extract_sigma_rule(predicted: dict[str, object], submission: str) -> str | None:
    """Extract sigma_rule from parsed output, falling back to regex on raw submission."""
    rule = predicted.get("sigma_rule")
    if rule:
        return str(rule)
    m = re.search(r'"sigma_rule"\s*:\s*"((?:[^"\\]|\\.)*)"', submission, re.DOTALL)
    if m:
        return m.group(1).replace("\\n", "\n").replace("\\t", "\t")
    return None


# ═══════════════════════════════════════════════════════════════════
# C0: CTI Alignment (max_score=1.25)
# ═══════════════════════════════════════════════════════════════════


class CTIAlignmentStrategy:
    """C0: Gate on CTI tool usage, then LLM-judge alignment score."""

    def __init__(self, prompts_dir: Path) -> None:
        self._renderer = TemplateRenderer(templates_dir=prompts_dir)

    async def score(self, ctx: ScoringContext, renderer: object) -> Score:
        if not detect_cti_usage(ctx.tool_steps):
            return Score(value=0.0, answer="No CTI tools used", explanation="No CTI tools used")

        detection_objective = criteria_str(ctx, "detection_objective")
        model_name = criteria_str(ctx, "model", "openai/azure/gpt-5-mini")
        alignment = await score_cti_alignment(
            detection_objective, ctx.tool_steps, model_name, self._renderer,
        )
        value = alignment * ctx.scorer.max_score
        return Score(
            value=value,
            answer=f"alignment={alignment:.3f}",
            explanation=f"alignment={alignment:.3f} score={value:.3f}/{ctx.scorer.max_score}",
        )


# ═══════════════════════════════════════════════════════════════════
# C1: MITRE Technique Jaccard (max_score=0.75)
# ═══════════════════════════════════════════════════════════════════


class MITREJaccardStrategy:
    """C1: Jaccard similarity of MITRE technique IDs in trajectory."""

    async def score(self, ctx: ScoringContext, renderer: object) -> Score:
        expected = criteria_list(ctx, "expected_techniques")
        if not expected:
            return Score(value=0.0, answer="No expected_techniques", explanation="No expected_techniques")

        j = detect_mitre_techniques(ctx.tool_steps, expected, submission=ctx.submission)
        value = j * ctx.scorer.max_score
        return Score(
            value=value,
            answer=f"Jaccard={j:.3f} expected={expected}",
            explanation=f"Jaccard={j:.3f} score={value:.3f}/{ctx.scorer.max_score}",
        )


# ═══════════════════════════════════════════════════════════════════
# C2: Data Exploration Jaccard (max_score=1.0)
# ═══════════════════════════════════════════════════════════════════


class DataExplorationStrategy:
    """C2: Jaccard similarity of explored data sources."""

    async def score(self, ctx: ScoringContext, renderer: object) -> Score:
        expected = criteria_list(ctx, "expected_data_sources")
        if not expected:
            return Score(value=0.0, answer="No expected_data_sources", explanation="No expected_data_sources")

        j = detect_data_exploration(ctx.tool_steps, expected)
        value = j * ctx.scorer.max_score
        return Score(
            value=value,
            answer=f"Jaccard={j:.3f} expected={expected}",
            explanation=f"Jaccard={j:.3f} score={value:.3f}/{ctx.scorer.max_score}",
        )


# ═══════════════════════════════════════════════════════════════════
# C3: Query Iteration (max_score=0.5)
# ═══════════════════════════════════════════════════════════════════


class QueryIterationStrategy:
    """C3: Binary — did the agent execute ≥2 unique successful KQL queries?"""

    async def score(self, ctx: ScoringContext, renderer: object) -> Score:
        passed = detect_query_iteration(ctx.tool_steps)
        value = ctx.scorer.max_score if passed else 0.0
        return Score(
            value=value,
            answer=f"passed={passed}",
            explanation=f"passed={passed} score={value:.3f}/{ctx.scorer.max_score}",
        )


# ═══════════════════════════════════════════════════════════════════
# C4: Detection Quality (max_score=6.5)
# ═══════════════════════════════════════════════════════════════════


class DetectionQualityStrategy:
    """C4: KQL F1 (weight 5.0) + Sigma rule quality (weight 1.5)."""

    def __init__(self, prompts_dir: Path) -> None:
        sys_path = prompts_dir / "sigma_quality_system.j2"
        usr_path = prompts_dir / "sigma_quality_user.j2"
        self._sigma_system = sys_path.read_text() if sys_path.exists() else ""
        self._sigma_user_tpl = usr_path.read_text() if usr_path.exists() else ""

    async def score(self, ctx: ScoringContext, renderer: object) -> Score:
        regex_patterns = criteria_dict(ctx, "regex_patterns")
        detection_objective = criteria_str(ctx, "detection_objective")
        model_name = criteria_str(ctx, "model", "openai/azure/gpt-5-mini")
        predicted = parse_model_output(ctx.submission)

        # F1 from KQL results (weight 5.0)
        f1 = 0.0
        if regex_patterns:
            if verify_results_from_tool_steps(predicted, ctx.tool_steps):
                f1 = score_kql_f1(predicted, regex_patterns)
            else:
                logger.warning("query_results failed tool verification — F1 = 0")

        # Sigma rule quality (weight 1.5)
        sigma = 0.0
        sigma_rule = _extract_sigma_rule(predicted, ctx.submission)
        if sigma_rule and self._sigma_system:
            predicted["sigma_rule"] = sigma_rule
            sigma = await score_sigma_rule(
                predicted, detection_objective,
                system_prompt=self._sigma_system,
                user_template=self._sigma_user_tpl,
                model_name=model_name,
            )

        raw = (f1 * 5.0) + (sigma * 1.5)
        value = min(raw, ctx.scorer.max_score)
        return Score(
            value=value,
            answer=f"F1={f1:.3f} Sigma={sigma:.3f}",
            explanation=f"F1={f1:.3f} Sigma={sigma:.3f} score={value:.3f}/{ctx.scorer.max_score}",
        )


__all__ = [
    "CTIAlignmentStrategy",
    "DataExplorationStrategy",
    "DetectionQualityStrategy",
    "MITREJaccardStrategy",
    "QueryIterationStrategy",
]
