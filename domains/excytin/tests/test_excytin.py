"""Tests for the Excytin Inspect task entrypoint."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from unittest.mock import patch, sentinel


def _load_excytin_module() -> ModuleType:
    module_path = Path(__file__).resolve().parent.parent / "excytin.py"
    spec = importlib.util.spec_from_file_location("test_excytin_domain", module_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_EXCYTIN_MODULE = _load_excytin_module()
excytin = _EXCYTIN_MODULE.excytin


class TestExcytinTaskEntrypoint:
    """Verify domain-specific task defaults are forwarded correctly."""

    def test_forwards_domain_default_judge_llm(self) -> None:
        """Excytin keeps its own default judge model when none is provided."""
        with patch.object(_EXCYTIN_MODULE, "create_task", return_value=sentinel.task) as mock_create_task:
            result = excytin()

        assert result is sentinel.task
        mock_create_task.assert_called_once_with(judge_llm="openai/azure/gpt-4.1")

    def test_forwards_custom_judge_llm_with_other_kwargs(self) -> None:
        """CLI-provided judge_llm overrides the domain default and preserves kwargs."""
        with patch.object(_EXCYTIN_MODULE, "create_task", return_value=sentinel.task) as mock_create_task:
            result = excytin(
                judge_llm="openai/azure/gpt-4.1-mini",
                task_filter="incident_5_*",
            )

        assert result is sentinel.task
        mock_create_task.assert_called_once_with(
            judge_llm="openai/azure/gpt-4.1-mini",
            task_filter="incident_5_*",
        )
