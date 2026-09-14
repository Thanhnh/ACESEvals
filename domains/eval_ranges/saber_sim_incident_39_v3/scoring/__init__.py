"""Domain scoring strategies shipped with SABER-SIM export bundles."""

from __future__ import annotations

from pathlib import Path

from .attack_impact import AttackImpactStrategy
from .recon_report_overlap import ReconReportOverlapStrategy


def get_strategies(domain_root: Path) -> dict[str, object]:
    """Return the exported domain scoring strategies."""
    return {
        "recon_report_overlap": ReconReportOverlapStrategy(domain_root),
        "attack_impact": AttackImpactStrategy(domain_root),
    }
