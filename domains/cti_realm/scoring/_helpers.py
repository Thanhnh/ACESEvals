"""Shared helpers for CTI Realm scoring strategies.

- Constants: tool-name sets for checkpoint detection.
- Criteria accessors: read ``DomainCriteria.model_extra`` fields from task YAML.
- Jaccard: set-similarity utility.
"""

from __future__ import annotations

from saber.scoring.context import ScoringContext

# Tools that indicate CTI research was performed (C0).
CTI_TOOLS: frozenset[str] = frozenset({
    "get_cti_reports_by_tag",
    "list_cti_report_tags",
})

# Tools that indicate data exploration (C2).
DATA_EXPLORATION_TOOLS: frozenset[str] = frozenset({
    "get_table_schema",
    "sample_table_data",
})


# ---------------------------------------------------------------------------
# DomainCriteria accessors
# ---------------------------------------------------------------------------


def criteria_extras(ctx: ScoringContext) -> dict[str, object]:
    """Return ``model_extra`` from ``DomainCriteria`` (or empty dict)."""
    from saber.config.models import DomainCriteria

    criteria = ctx.scorer.criteria
    if isinstance(criteria, DomainCriteria):
        return criteria.model_extra or {}
    return {}


def criteria_str(ctx: ScoringContext, key: str, default: str = "") -> str:
    value = criteria_extras(ctx).get(key, default)
    return str(value) if value is not None else default


def criteria_list(ctx: ScoringContext, key: str) -> list[str]:
    value = criteria_extras(ctx).get(key, [])
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [value]
    return []


def criteria_dict(ctx: ScoringContext, key: str) -> dict[str, str]:
    value = criteria_extras(ctx).get(key, {})
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    return {}


# ---------------------------------------------------------------------------
# Set similarity
# ---------------------------------------------------------------------------


def jaccard(found: set[str], expected: set[str]) -> float:
    """Jaccard similarity coefficient between two sets."""
    union = found | expected
    return len(found & expected) / len(union) if union else 0.0
