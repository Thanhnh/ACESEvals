"""Tests for cti_realm/scoring/__init__.py — factory function."""

from __future__ import annotations

from pathlib import Path

from cti_realm.scoring import (
    CTIAlignmentStrategy,
    DataExplorationStrategy,
    DetectionQualityStrategy,
    MITREJaccardStrategy,
    QueryIterationStrategy,
    get_strategies,
)


class TestGetStrategies:
    """Tests for the get_strategies factory."""

    def test_returns_five_strategies(self, tmp_path: Path) -> None:
        strategies = get_strategies(tmp_path)
        assert len(strategies) == 5

    def test_strategy_names(self, tmp_path: Path) -> None:
        strategies = get_strategies(tmp_path)
        expected_keys = {
            "cti_alignment",
            "mitre_jaccard",
            "data_exploration",
            "query_iteration",
            "detection_quality",
        }
        assert set(strategies.keys()) == expected_keys

    def test_strategy_types(self, tmp_path: Path) -> None:
        strategies = get_strategies(tmp_path)
        assert isinstance(strategies["cti_alignment"], CTIAlignmentStrategy)
        assert isinstance(strategies["mitre_jaccard"], MITREJaccardStrategy)
        assert isinstance(strategies["data_exploration"], DataExplorationStrategy)
        assert isinstance(strategies["query_iteration"], QueryIterationStrategy)
        assert isinstance(strategies["detection_quality"], DetectionQualityStrategy)

    def test_all_strategies_have_score_method(self, tmp_path: Path) -> None:
        strategies = get_strategies(tmp_path)
        for name, strat in strategies.items():
            assert hasattr(strat, "score"), f"{name} missing score method"
            assert callable(strat.score), f"{name}.score not callable"
