# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""KQL development scoring — F1 with tool verification.

Public API:
- ``score_kql_f1``          — F1 score from regex patterns vs query results.
- ``verify_results_from_tool_steps`` — anti-hallucination check.
- ``parse_kusto_response``  — parse raw Kusto API JSON into row dicts.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from saber.scoring.context import ToolStep

logger = logging.getLogger("saber.domains.cti_realm.scoring.kql")


# ---------------------------------------------------------------------------
# Kusto response parsing
# ---------------------------------------------------------------------------


def parse_kusto_response(response_str: str) -> list[dict[str, object]]:
    """Parse Kusto API output into a list of row dicts.

    Handles three formats:
    1. Native Kusto: ``{"Tables": [{"Columns": [...], "Rows": [...]}]}``
    2. stdout-wrapped: ``{"stdout": "<json>"}`` or ``{"data": {"stdout": ...}}``
    3. Already-parsed list of dicts.

    Returns an empty list when the input cannot be parsed.
    """
    try:
        data = json.loads(response_str) if isinstance(response_str, str) else response_str
    except (json.JSONDecodeError, TypeError):
        return []

    # Unwrap stdout wrappers produced by sandbox exec
    if isinstance(data, dict):
        stdout = data.get("stdout")
        if not stdout:
            data_field = data.get("data", {})
            if isinstance(data_field, dict):
                stdout = data_field.get("stdout", "")
        if stdout and isinstance(stdout, str):
            try:
                data = json.loads(stdout)
            except (json.JSONDecodeError, TypeError):
                return []
        elif stdout and isinstance(stdout, dict):
            data = stdout

    # Native Kusto format
    if isinstance(data, dict) and "Tables" in data:
        tables = data.get("Tables", [])
        if tables and "Rows" in tables[0]:
            columns = [col["ColumnName"] for col in tables[0].get("Columns", [])]
            rows = tables[0].get("Rows", [])
            return [dict(zip(columns, row)) for row in rows]

    # Already a list of row dicts
    if isinstance(data, list):
        return data

    return []


# ---------------------------------------------------------------------------
# Tool-output verification (anti-hallucination)
# ---------------------------------------------------------------------------


def _normalize_value(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _rows_match(predicted_row: dict[str, object], tool_row: dict[str, object]) -> bool:
    """True when every common field in *predicted_row* equals *tool_row*."""
    pred = {k.lower(): _normalize_value(v) for k, v in predicted_row.items()}
    tool = {k.lower(): _normalize_value(v) for k, v in tool_row.items()}
    return all(tool.get(k) == v for k, v in pred.items() if k in tool)


def verify_results_from_tool_steps(
    predicted: dict[str, object],
    tool_steps: tuple[ToolStep, ...],
) -> bool:
    """Verify ``query_results`` came from real ``execute_kql_query`` responses.

    Returns True if every predicted row is found in an actual tool response,
    or if there are no results to verify.  Returns False if results appear
    fabricated (no matching tool output).
    """
    results = predicted.get("query_results")
    if not results:
        return True

    if isinstance(results, str):
        try:
            results = json.loads(results)
        except json.JSONDecodeError:
            return False

    if not isinstance(results, list) or not results:
        return True

    # Were any KQL queries executed?
    kql_steps = [s for s in tool_steps if s.tool_name == "execute_kql_query"]
    if not kql_steps:
        logger.warning("query_results present but execute_kql_query never called")
        return False

    # Collect all rows from every KQL tool response
    all_tool_rows: list[dict[str, object]] = []
    for step in kql_steps:
        if step.output:
            all_tool_rows.extend(parse_kusto_response(step.output))

    if not all_tool_rows:
        logger.warning("No parseable rows in any execute_kql_query response")
        return False

    # Every predicted row must match at least one tool row
    verified = sum(
        1
        for row in results
        if isinstance(row, dict) and any(_rows_match(row, tr) for tr in all_tool_rows)
    )
    if verified < len(results):
        logger.warning("Only %d/%d predicted rows verified against tool output", verified, len(results))
        return False

    return True


# ---------------------------------------------------------------------------
# F1 scoring
# ---------------------------------------------------------------------------


def score_kql_f1(
    predicted: dict[str, object],
    regex_patterns: dict[str, str],
) -> float:
    """Compute field-slot F1 between query results and ground-truth regex patterns.

    Precision  = matched_fields / (num_patterns x num_rows)
    Recall     = unique_fields_found / num_patterns
    Score      = F1(precision, recall),  capped at 1.0.

    Args:
        predicted: Parsed model output; must contain ``query_results``.
        regex_patterns: ``{field_name: regex_pattern}`` from ground truth.

    Returns:
        Float in [0, 1].
    """
    if not regex_patterns:
        return 0.0

    results = predicted.get("query_results")
    if not results:
        return 0.0

    if isinstance(results, str):
        try:
            results = json.loads(results)
        except json.JSONDecodeError:
            return 0.0

    if not isinstance(results, list) or not results:
        return 0.0

    # Count field-level matches
    total_matched = 0
    fields_found: set[str] = set()

    for row in results:
        if not isinstance(row, dict):
            continue
        for field, pattern in regex_patterns.items():
            for row_field, row_value in row.items():
                if row_field.lower() == field.lower():
                    try:
                        if re.search(pattern, str(row_value)):
                            total_matched += 1
                            fields_found.add(field)
                    except re.error:
                        pass
                    break

    total_slots = len(regex_patterns) * len(results)
    precision = total_matched / total_slots if total_slots > 0 else 0.0
    recall = len(fields_found) / len(regex_patterns) if regex_patterns else 0.0

    if precision + recall == 0:
        return 0.0
    return min(1.0, 2 * precision * recall / (precision + recall))
