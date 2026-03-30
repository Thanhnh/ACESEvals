"""CTI Realm scoring strategies for the SABER thin library.

Five checkpoint strategies, one per scoring checkpoint (C0–C4).
``saber_overall`` aggregates them via the default weighted-average
path: Σ(score) / Σ(max_score) = total / 10.
"""

from pathlib import Path

from saber.scoring.strategies import SaberScoringStrategy

from .strategies import (
    CTIAlignmentStrategy,
    DataExplorationStrategy,
    DetectionQualityStrategy,
    MITREJaccardStrategy,
    QueryIterationStrategy,
)

__all__ = [
    "CTIAlignmentStrategy",
    "DataExplorationStrategy",
    "DetectionQualityStrategy",
    "MITREJaccardStrategy",
    "QueryIterationStrategy",
    "get_strategies",
]


def get_strategies(
    domain_root: Path,
) -> dict[str, SaberScoringStrategy]:
    """Create the CTI Realm scoring strategies.

    Auto-discovered by ``create_task`` when a ``scoring/`` package is
    present in the domain directory.

    Args:
        domain_root: Path to the domain root directory.

    Returns:
        Mapping of strategy name to strategy instance.
    """
    prompts_dir = domain_root / "prompts" / "judge"
    return {
        "cti_alignment": CTIAlignmentStrategy(prompts_dir),
        "mitre_jaccard": MITREJaccardStrategy(),
        "data_exploration": DataExplorationStrategy(),
        "query_iteration": QueryIterationStrategy(),
        "detection_quality": DetectionQualityStrategy(prompts_dir),
    }
