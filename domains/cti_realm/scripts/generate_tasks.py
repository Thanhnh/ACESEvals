"""Generate SABER task YAML files from CTI Realm JSONL datasets.

Reads ``dataset_samples_stratified_{N}.jsonl`` and
``dataset_answers_stratified_{N}.jsonl``, merges them by ``id``,
and produces ``tasks/cti_realm_{N}/cti_realm_{N}.yaml``.

Can be run standalone or called programmatically from setup hooks.

Usage::

    python -m cti_realm.scripts.generate_tasks --data-dir ./data --size 25
    python -m cti_realm.scripts.generate_tasks --data-dir ./data --size 50
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import yaml

logger = logging.getLogger("domains.cti_realm.scripts.generate_tasks")

# Platform mapping from task_id prefix
_PLATFORM_MAP = {
    "linux": "Linux",
    "aks": "AKS",
    "cloud": "Cloud",
}


def _platform_from_id(task_id: str) -> str:
    """Derive platform name from task_id prefix."""
    prefix = task_id.split("_")[0]
    return _PLATFORM_MAP.get(prefix, prefix.capitalize())


def _build_task(
    task_id: str,
    detection_description: str,
    mitre_techniques: list[str],
    data_sources: list[str],
    regex_patterns: dict[str, str],
) -> dict:
    """Build a single task dict from JSONL fields."""
    platform = _platform_from_id(task_id)

    return {
        "task_id": task_id,
        "title": detection_description[:60] + "...",
        "description": f"DETECTION OBJECTIVE:\n{detection_description}",
        "inherit_shared": True,
        "timeout": 1800,
        "initial_context": {
            "detection_objective": detection_description,
            "question": "Develop both Sigma rule and KQL query with actual query results demonstrating detection effectiveness",
            "platform": platform,
            "mitre_techniques": mitre_techniques,
            "data_sources": data_sources,
        },
        "scoring": {
            "cti_alignment": {
                "c0_cti_analysis": {
                    "target": "trajectory",
                    "detection_objective": detection_description,
                    "model": "openai/azure/gpt-5-mini",
                    "max_score": 1.25,
                    "weight": 1.0,
                },
            },
            "mitre_jaccard": {
                "c1_mitre_techniques": {
                    "target": "trajectory",
                    "expected_techniques": mitre_techniques,
                    "max_score": 0.75,
                    "weight": 1.0,
                },
            },
            "data_exploration": {
                "c2_data_exploration": {
                    "target": "trajectory",
                    "expected_data_sources": data_sources,
                    "max_score": 1.0,
                    "weight": 1.0,
                },
            },
            "query_iteration": {
                "c3_query_iteration": {
                    "target": "trajectory",
                    "max_score": 0.5,
                    "weight": 1.0,
                },
            },
            "detection_quality": {
                "c4_detection_quality": {
                    "target": "trajectory",
                    "detection_objective": detection_description,
                    "regex_patterns": regex_patterns,
                    "max_score": 6.5,
                    "weight": 1.0,
                },
            },
        },
    }


def _load_jsonl(path: Path) -> list[dict]:
    """Load a JSONL file into a list of dicts."""
    records = []
    with open(path) as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                records.append(json.loads(stripped))
    return records


def generate_tasks(data_dir: Path, size: int, output_dir: Path) -> Path:
    """Generate a task YAML file from JSONL dataset files.

    Args:
        data_dir: Directory containing ``dataset_samples_stratified_{size}.jsonl``
            and ``dataset_answers_stratified_{size}.jsonl``.
        size: Dataset size (25 or 50).
        output_dir: Directory to write the output YAML to
            (e.g., ``tasks/cti_realm_25/``).

    Returns:
        Path to the generated YAML file.

    Raises:
        FileNotFoundError: If JSONL files are missing.
        ValueError: If samples and answers don't match.
    """
    samples_path = data_dir / f"dataset_samples_stratified_{size}.jsonl"
    answers_path = data_dir / f"dataset_answers_stratified_{size}.jsonl"

    if not samples_path.exists():
        raise FileNotFoundError(f"Missing: {samples_path}")
    if not answers_path.exists():
        raise FileNotFoundError(f"Missing: {answers_path}")

    # Load and merge by id
    samples = {r["id"]: r for r in _load_jsonl(samples_path)}
    answers = {r["id"]: r for r in _load_jsonl(answers_path)}

    if set(samples.keys()) != set(answers.keys()):
        missing = set(samples.keys()) ^ set(answers.keys())
        raise ValueError(f"Samples/answers ID mismatch: {missing}")

    # Build tasks in ID order (sorted for determinism)
    tasks = []
    for task_id in sorted(samples.keys()):
        sample = samples[task_id]
        answer = answers[task_id]
        gt = sample["ground_truth"]

        task = _build_task(
            task_id=task_id,
            detection_description=answer["detection_description"],
            mitre_techniques=gt["mitre_techniques"],
            data_sources=gt["data_sources"],
            regex_patterns=gt["regex_patterns"],
        )
        tasks.append(task)

    # Write YAML
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"cti_realm_{size}.yaml"

    with open(output_path, "w") as f:
        yaml.dump(
            {"tasks": tasks},
            f,
            default_flow_style=False,
            sort_keys=False,
            width=120,
            allow_unicode=True,
        )

    logger.info("Generated %d tasks → %s", len(tasks), output_path)
    return output_path


def main() -> None:
    """CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate CTI Realm task YAML from JSONL")
    parser.add_argument("--data-dir", type=Path, required=True, help="Directory with JSONL files")
    parser.add_argument("--size", type=int, required=True, choices=[25, 50], help="Dataset size")
    parser.add_argument("--output-dir", type=Path, default=None, help="Output directory (default: tasks/cti_realm_{size}/)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)

    output_dir = args.output_dir or Path(__file__).parent.parent / "tasks" / f"cti_realm_{args.size}"
    generate_tasks(args.data_dir, args.size, output_dir)


if __name__ == "__main__":
    main()
