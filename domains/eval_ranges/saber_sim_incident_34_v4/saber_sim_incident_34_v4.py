"""SABER-SIM — Simulated Azure Cloud Attack domain for Inspect AI."""
import os
import shutil
from pathlib import Path

from inspect_ai import Task, task
from saber.task import create_task

# SABER reads sandbox.compose.yml; symlink where possible, copy on
# filesystems that don't allow it (Windows without developer mode).
def _link_or_copy(link_path: Path, target_name: str) -> None:
    if link_path.exists() or link_path.is_symlink():
        link_path.unlink()
    try:
        link_path.symlink_to(target_name)
    except OSError:
        shutil.copy2(link_path.parent / target_name, link_path)


def _activate_scenario_compose(task_filter: str | None) -> None:
    """Select the compose file for the scenario targeted by task_filter."""
    if not task_filter:
        return

    domain_root = Path(__file__).resolve().parent
    compose_dir = domain_root / "compose"
    if not compose_dir.is_dir():
        return

    sandbox_path = compose_dir / "sandbox.compose.yaml"
    # saber accepts a list or a comma-separated string of task filters.
    patterns = task_filter if isinstance(task_filter, list) else str(task_filter).split(",")
    prefixes = [p.strip().rstrip("*").rstrip("_") for p in patterns if p.strip()]
    candidates = []
    for compose_file in sorted(compose_dir.iterdir()):
        if compose_file.name == "sandbox.compose.yaml" or not compose_file.name.endswith(".compose.yaml"):
            continue
        scenario_name = compose_file.name.removesuffix(".compose.yaml")
        if any(scenario_name.startswith(p) or p.startswith(scenario_name) for p in prefixes):
            candidates.append(compose_file)

    if not candidates:
        raise ValueError(f"No scenario compose matches task_filter={task_filter!r}")
    if len(candidates) > 1:
        names = ", ".join(candidate.name for candidate in candidates)
        raise ValueError(f"task_filter={task_filter!r} matches multiple scenario compose files: {names}")

    selected = candidates[0]
    if sandbox_path.exists() and sandbox_path.read_text().strip() == selected.read_text().strip():
        return

    shutil.copy2(selected, sandbox_path)
    _link_or_copy(compose_dir / "sandbox.compose.yml", "sandbox.compose.yaml")

@task
def saber_sim_incident_34_v4(**kwargs: str | None) -> Task:
    """SABER-SIM — Simulated Azure Cloud Attack domain."""
    _activate_scenario_compose(kwargs.get("task_filter"))
    if "judge_llm" not in kwargs:
        kwargs["judge_llm"] = os.environ.get("JUDGE_MODEL", "openai/azure/gpt-5.4")
    return create_task(**kwargs)
