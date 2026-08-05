#!/usr/bin/env python3
"""Convert Opus 5 regenerated QA (the entity-email-fixed `latest_cleaned` data)
into SABER task YAMLs, matching the deployed ``latest_test_set`` schema exactly.

Input : secrl ``secgym/questions/opus5/{test,train}/incident_<id>_qa_opus5_cleaned.json``
Output: ``domains/excytin/tasks/latest_cleaned_{test,train}_set/incident_<id>/incident_<id>_<i>.yaml``

Per-incident ``shared.yaml`` is copied from the corresponding ``latest_*`` set
with the ``dataset:`` field rewritten to the cleaned set name.
"""
import argparse
import json
import os
import re
from pathlib import Path

DEFAULT_INPUT = os.path.expanduser("~/repos/secrl/secgym/questions/opus5")
DEFAULT_TASKS = Path(__file__).resolve().parent.parent / "domains/excytin/tasks"
SPLIT_TO_SET = {"test": "latest_cleaned_test_set", "train": "latest_cleaned_train_set"}
SPLIT_TO_SRC = {"test": "latest_test_set", "train": "latest_train_set"}


def yaml_escape(value: str) -> str:
    """Escape a string for a single-quoted single-line YAML scalar."""
    if value is None:
        return ""
    # Drop control chars; collapse any newlines/tabs to spaces (single-line scalar)
    value = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", value)
    value = value.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    value = re.sub(r"  +", " ", value).strip()
    return value.replace("'", "''")


def extract_incident(name: str) -> str:
    m = re.search(r"incident_(\d+)_", name)
    return m.group(1) if m else "0"


def create_task_yaml(task_id: str, question: str, context: str, answer: str,
                     solution: list[str]) -> str:
    q, c, a = yaml_escape(question), yaml_escape(context), yaml_escape(answer)
    n = len(solution)
    cp_score = round(1.0 / n, 3) if n else 1.0

    checkpoints = ""
    for i, step in enumerate(solution, 1):
        checkpoints += (
            f"      checkpoint_{i}:\n"
            f"        target: trajectory\n"
            f"        max_score: {cp_score}\n"
            f"        weight: 1.0\n"
            f"        title: Checkpoint {i}\n"
            f"        description: '{yaml_escape(step)}'\n"
        )

    # scoring_aggregation: max(submission, sum(checkpoints))
    if n:
        cp_list = "      - - " + "\n        - ".join(f"checkpoint_{i}" for i in range(1, n + 1))
        agg = f"      - submission\n{cp_list}"
    else:
        agg = "      - submission"

    return (
        "tasks:\n"
        f"- task_id: {task_id}\n"
        f"  title: {task_id}\n"
        f"  description: '{q}'\n"
        "  inherit_shared: true\n"
        "  initial_context:\n"
        f"    incident_context: '{c}'\n"
        f"    question: '{q}'\n"
        "    # Main task submission evaluation - uses LLM-as-a-judge by default\n"
        '    # To use static matching instead, change strategy to "static" and set:\n'
        "    #   criteria:\n"
        "    #     expected_answers:\n"
        f"    #       - '{a}'\n"
        "  scoring:\n"
        "    llm_judge:\n"
        '      model: "{judge_llm}"\n'
        "      steps_per_message: 50\n"
        "      judge_system_template: judge/checkpoint_judge_system.md\n"
        "      judge_user_template: judge/checkpoint_judge_user.md\n"
        "      submission:\n"
        "        target: submission\n"
        "        judge_system_template: judge/submission_judge_system.md\n"
        "        judge_user_template: judge/submission_judge_user.md\n"
        f"        description: '{a}'\n"
        "        max_score: 1.0\n"
        f"{checkpoints}"
        "  scoring_aggregation:\n"
        "    max:\n"
        "      scores:\n"
        f"{agg}\n"
    )


def write_shared(inc: str, split: str, tasks_dir: Path) -> None:
    cleaned_set = SPLIT_TO_SET[split]
    src_set = SPLIT_TO_SRC[split]
    src = tasks_dir / src_set / f"incident_{inc}" / "shared.yaml"
    dst_dir = tasks_dir / cleaned_set / f"incident_{inc}"
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / "shared.yaml"
    if src.exists():
        text = src.read_text()
        text = re.sub(r"^dataset:\s*\S+", f"dataset: {cleaned_set}", text, count=1, flags=re.M)
        dst.write_text(text)
    else:
        raise FileNotFoundError(f"missing source shared.yaml: {src}")


def convert(input_dir: str, tasks_dir: Path, splits: list[str]) -> None:
    for split in splits:
        cleaned_set = SPLIT_TO_SET[split]
        in_split = Path(input_dir) / split
        total = 0
        for jf in sorted(in_split.glob("incident_*_qa_opus5_cleaned.json")):
            inc = extract_incident(jf.name)
            questions = json.load(open(jf, encoding="utf-8"))
            valid = [q for q in questions if q.get("question") and q.get("answer")]
            inc_dir = tasks_dir / cleaned_set / f"incident_{inc}"
            inc_dir.mkdir(parents=True, exist_ok=True)
            for i, qa in enumerate(valid, 1):
                tid = f"incident_{inc}_{cleaned_set}_task_{i}"
                yaml_text = create_task_yaml(
                    tid, qa.get("question", ""), qa.get("context", ""),
                    qa.get("answer", ""), qa.get("solution", []) or [],
                )
                (inc_dir / f"incident_{inc}_{i}.yaml").write_text(yaml_text)
            write_shared(inc, split, tasks_dir)
            total += len(valid)
            print(f"  [{split}] incident_{inc}: {len(valid)} tasks")
        print(f"[{split}] total: {total} tasks -> {cleaned_set}/")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input-dir", default=DEFAULT_INPUT)
    ap.add_argument("--tasks-dir", default=str(DEFAULT_TASKS))
    ap.add_argument("--splits", nargs="*", default=["test", "train"])
    args = ap.parse_args()
    convert(args.input_dir, Path(args.tasks_dir), args.splits)


if __name__ == "__main__":
    main()
