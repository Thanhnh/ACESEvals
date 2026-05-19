# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Trajectory checkpoint detectors for CTI Realm scoring (C0–C3).

Pure functions that analyse ``ToolStep`` tuples and return
simple results (bool or float).  Used by the checkpoint
strategy classes in ``strategies.py``.
"""

from __future__ import annotations

import json
import logging
import re

from inspect_ai.model import GenerateConfig, get_model
from saber.scoring.context import ToolStep
from saber.scoring.templates import TemplateRenderer

from ._helpers import CTI_TOOLS, DATA_EXPLORATION_TOOLS, jaccard
from ._kql import parse_kusto_response

logger = logging.getLogger("saber.domains.cti_realm.scoring.checkpoints")


# ---------------------------------------------------------------------------
# C0: CTI Report Usage
# ---------------------------------------------------------------------------


def detect_cti_usage(steps: tuple[ToolStep, ...]) -> bool:
    """True if the agent called any CTI report tools."""
    return any(s.tool_name in CTI_TOOLS for s in steps)


def _extract_reports_accessed(steps: tuple[ToolStep, ...]) -> list[str]:
    """Extract unique report titles from CTI tool outputs."""
    titles: list[str] = []
    for step in steps:
        if step.tool_name == "get_cti_reports_by_tag" and step.output:
            for m in re.findall(r'"title"\s*:\s*"([^"]+)"', step.output):
                if m not in titles:
                    titles.append(m)
    return titles


async def score_cti_alignment(
    detection_objective: str,
    steps: tuple[ToolStep, ...],
    model_name: str,
    renderer: TemplateRenderer,
) -> float:
    """LLM-judge: evaluate CTI research relevance via Jinja2 templates.

    Uses ``cti_alignment_system.j2`` / ``cti_alignment_user.j2``.
    Returns 0.0 on template or LLM errors.
    """
    from saber.scoring.context import EpisodeContext

    from ._parsing import extract_score_and_reasoning_from_text

    reports = _extract_reports_accessed(steps)
    reports_summary = (
        f"{len(reports)} reports: {', '.join(reports)}"
        if reports
        else "No reports accessed"
    )

    ctx: dict[str, object] = {
        "question": detection_objective,
        "episode": EpisodeContext(steps=steps),
        "reports_summary": reports_summary,
    }

    try:
        system_prompt = renderer.render("cti_alignment_system.j2", ctx)
        user_prompt = renderer.render("cti_alignment_user.j2", ctx)
    except Exception:
        logger.warning("Failed to render CTI alignment templates — skipping C0 LLM judge")
        return 0.0

    from inspect_ai.model import ChatMessageSystem, ChatMessageUser

    judge = get_model(model_name)
    response = await judge.generate(
        [ChatMessageSystem(content=system_prompt), ChatMessageUser(content=user_prompt)],
        config=GenerateConfig(temperature=0.0, max_tokens=5000),
    )

    match = re.search(r"\{[\s\S]*\}", response.completion)
    if match:
        try:
            return min(max(float(json.loads(match.group()).get("score", 0.0)), 0.0), 1.0)
        except (json.JSONDecodeError, ValueError):
            pass

    logger.warning("No valid JSON in C0 judge response, using fallback parser")
    score, _ = extract_score_and_reasoning_from_text(response.completion)
    return min(max(score, 0.0), 1.0)


# ---------------------------------------------------------------------------
# C1: MITRE Technique Jaccard
# ---------------------------------------------------------------------------


def detect_mitre_techniques(
    steps: tuple[ToolStep, ...],
    expected: list[str],
    submission: str = "",
) -> float:
    """Jaccard similarity of MITRE technique IDs found in the trajectory."""
    if not expected:
        return 0.0
    pattern = r"T\d{4}(?:\.\d{3})?"
    expected_set = {t.upper() for t in expected}
    found: set[str] = set()
    for step in steps:
        for text in (step.output, str(step.tool_input), step.assistant_message or "", step.reasoning or ""):
            found.update(m.upper() for m in re.findall(pattern, text, re.IGNORECASE))
    if submission:
        found.update(m.upper() for m in re.findall(pattern, submission, re.IGNORECASE))
    # Match inspect_evals: Jaccard on matched-only vs expected (recall-style)
    matched = found & expected_set
    return jaccard(matched, expected_set)


# ---------------------------------------------------------------------------
# C2: Data Exploration Jaccard
# ---------------------------------------------------------------------------


def detect_data_exploration(
    steps: tuple[ToolStep, ...],
    expected: list[str],
) -> float:
    """Jaccard similarity of table names explored via schema/sample tools."""
    if not expected:
        return 0.0
    expected_set = {s.lower() for s in expected}
    found: set[str] = set()
    for step in steps:
        if step.tool_name in DATA_EXPLORATION_TOOLS:
            name = step.tool_input.get("table_name", "")
            if name:
                found.add(str(name).lower())
    return jaccard(found, expected_set)


# ---------------------------------------------------------------------------
# C3: Query Iteration
# ---------------------------------------------------------------------------


def detect_query_iteration(steps: tuple[ToolStep, ...]) -> bool:
    """True if >=2 unique KQL queries returned parseable results."""
    unique: list[str] = []
    for step in steps:
        if step.tool_name != "execute_kql_query":
            continue
        if not step.output or step.is_error or not parse_kusto_response(step.output):
            continue
        normalized = " ".join(str(step.tool_input.get("query", "")).lower().split())
        if all(" ".join(q.lower().split()) != normalized for q in unique):
            unique.append(str(step.tool_input.get("query", "")))
    return len(unique) >= 2
