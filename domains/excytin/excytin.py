# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Excytin database forensics and incident response domain for Inspect AI.

This module exposes the Excytin domain as an Inspect AI task that can be
evaluated with commands like:

    inspect eval domains/excytin --model openai/gpt-4
    inspect eval domains/excytin -T task_filter=forensics_* --model anthropic/claude-3-opus
    inspect eval domains/excytin -T judge_llm=openai/azure/gpt-4.1-mini --model openai/gpt-4
"""

from inspect_ai import Task, task

from saber.task import create_task


@task
def excytin(
    **kwargs: str | None,
) -> Task:
    """Excytin database forensics and incident response domain.

    Database forensics and incident response benchmark — agent investigates
    compromised database environments to identify and remediate security
    incidents.

    Args:
        **kwargs: Keyword arguments forwarded to ``create_task``
            (e.g., task_filter, agent, rebuild, run_preflight,
            keep_permanent, persona_file).

    Returns:
        Fully configured inspect_ai Task.
    """

    # We require a judge LLM, so default it to be "apenai/azure/gpt-4.1" if not specified. This
    # preserves the original hard-coded LLM judge behavior when the var isn't provided
    if "judge_llm" not in kwargs:
        kwargs["judge_llm"] = "openai/azure/gpt-4.1"

    return create_task(**kwargs)
