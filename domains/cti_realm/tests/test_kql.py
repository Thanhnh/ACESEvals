# Copyright (c) Microsoft Corporation.
# Licensed under the MIT license.

"""Tests for cti_realm/scoring/_kql.py — KQL F1 scoring."""

from __future__ import annotations

import json

import pytest

from cti_realm.scoring._kql import (
    score_kql_f1,
    verify_results_from_tool_steps,
)
from saber.scoring.context import ToolStep


# =====================================================================
# score_kql_f1
# =====================================================================


class TestScoreKqlF1:
    def test_missing_query_results_returns_zero(self) -> None:
        assert score_kql_f1({}, {"f": ".*"}) == 0.0

    def test_empty_patterns_returns_zero(self) -> None:
        assert score_kql_f1({"query_results": [{"a": "1"}]}, {}) == 0.0

    def test_empty_results_list_returns_zero(self) -> None:
        assert score_kql_f1({"query_results": []}, {"f": ".*"}) == 0.0

    def test_string_query_results_parsed(self) -> None:
        predicted: dict[str, object] = {
            "query_results": json.dumps([{"FileName": "malware.exe"}])
        }
        assert score_kql_f1(predicted, {"FileName": r"malware\.exe"}) > 0.0

    def test_invalid_string_query_results_returns_zero(self) -> None:
        assert score_kql_f1({"query_results": "not json"}, {"f": ".*"}) == 0.0

    def test_exact_match_single_row(self) -> None:
        predicted: dict[str, object] = {
            "query_results": [{"FileName": "malware.exe", "ProcessId": "1234"}]
        }
        score = score_kql_f1(predicted, {"FileName": r"malware\.exe", "ProcessId": r"1234"})
        assert score > 0.0

    def test_partial_match(self) -> None:
        predicted: dict[str, object] = {
            "query_results": [
                {"FileName": "malware.exe", "ProcessId": "wrong"},
                {"FileName": "clean.exe", "ProcessId": "5678"},
            ]
        }
        score = score_kql_f1(predicted, {"FileName": r"malware\.exe", "ProcessId": r"1234"})
        assert 0.0 < score < 1.0

    def test_perfect_rows_full_f1(self) -> None:
        predicted: dict[str, object] = {
            "query_results": [
                {"FileName": "mal.exe", "PID": "1"},
                {"FileName": "mal.exe", "PID": "1"},
                {"FileName": "mal.exe", "PID": "1"},
            ]
        }
        score = score_kql_f1(predicted, {"FileName": r"mal\.exe", "PID": r"1"})
        assert score == pytest.approx(1.0)

    def test_non_dict_rows_ignored(self) -> None:
        predicted: dict[str, object] = {
            "query_results": ["string_row", {"FileName": "ok.exe"}]
        }
        score = score_kql_f1(predicted, {"FileName": r"ok\.exe"})
        assert score > 0.0

    def test_score_capped_at_one(self) -> None:
        predicted: dict[str, object] = {
            "query_results": [{"F": "v"} for _ in range(10)]
        }
        assert score_kql_f1(predicted, {"F": r"v"}) <= 1.0

    def test_case_insensitive_field_matching(self) -> None:
        predicted: dict[str, object] = {
            "query_results": [{"filename": "malware.exe"}]
        }
        score = score_kql_f1(predicted, {"FileName": r"malware\.exe"})
        assert score > 0.0

    def test_invalid_regex_pattern_skipped(self) -> None:
        predicted: dict[str, object] = {
            "query_results": [{"field": "value"}]
        }
        assert score_kql_f1(predicted, {"field": r"[invalid(regex"}) == 0.0


# =====================================================================
# verify_results_from_tool_steps
# =====================================================================


def _make_step(
    *,
    tool_name: str = "execute_kql_query",
    tool_input: dict[str, object] | None = None,
    output: str = "",
) -> ToolStep:
    return ToolStep(
        step_number=1,
        tool_name=tool_name,
        tool_input=tool_input or {},
        output=output,
    )


class TestVerifyResultsFromToolSteps:
    def test_no_results_returns_true(self) -> None:
        assert verify_results_from_tool_steps({}, ()) is True

    def test_no_kql_calls_returns_false(self) -> None:
        predicted: dict[str, object] = {"query_results": [{"F": "v"}]}
        step = _make_step(tool_name="get_table_schema", output="schema")
        assert verify_results_from_tool_steps(predicted, (step,)) is False

    def test_kql_called_but_no_parseable_output(self) -> None:
        predicted: dict[str, object] = {"query_results": [{"F": "v"}]}
        step = _make_step(output="not json")
        assert verify_results_from_tool_steps(predicted, (step,)) is False

    def test_matching_kusto_response(self) -> None:
        import json
        kusto_output = json.dumps({
            "Tables": [{
                "Columns": [{"ColumnName": "FileName"}],
                "Rows": [["cmd.exe"]],
            }]
        })
        predicted: dict[str, object] = {
            "query_results": [{"FileName": "cmd.exe"}]
        }
        step = _make_step(output=kusto_output)
        assert verify_results_from_tool_steps(predicted, (step,)) is True

    def test_fabricated_results_rejected(self) -> None:
        import json
        kusto_output = json.dumps({
            "Tables": [{
                "Columns": [{"ColumnName": "FileName"}],
                "Rows": [["legit.exe"]],
            }]
        })
        predicted: dict[str, object] = {
            "query_results": [{"FileName": "fabricated.exe"}]
        }
        step = _make_step(output=kusto_output)
        assert verify_results_from_tool_steps(predicted, (step,)) is False

    def test_stdout_wrapped_response(self) -> None:
        import json
        inner = json.dumps({
            "Tables": [{
                "Columns": [{"ColumnName": "F"}],
                "Rows": [["v"]],
            }]
        })
        step = _make_step(output=json.dumps({"stdout": inner}))
        predicted: dict[str, object] = {"query_results": [{"F": "v"}]}
        assert verify_results_from_tool_steps(predicted, (step,)) is True

    def test_string_query_results_parsed(self) -> None:
        import json
        kusto_output = json.dumps({
            "Tables": [{
                "Columns": [{"ColumnName": "F"}],
                "Rows": [["v"]],
            }]
        })
        predicted: dict[str, object] = {
            "query_results": json.dumps([{"F": "v"}])
        }
        step = _make_step(output=kusto_output)
        assert verify_results_from_tool_steps(predicted, (step,)) is True

    def test_empty_results_list_returns_true(self) -> None:
        predicted: dict[str, object] = {"query_results": []}
        assert verify_results_from_tool_steps(predicted, ()) is True

    def test_multiple_kql_steps_combined(self) -> None:
        import json
        out1 = json.dumps({
            "Tables": [{
                "Columns": [{"ColumnName": "F"}],
                "Rows": [["a"]],
            }]
        })
        out2 = json.dumps({
            "Tables": [{
                "Columns": [{"ColumnName": "F"}],
                "Rows": [["b"]],
            }]
        })
        steps = (
            _make_step(output=out1),
            _make_step(output=out2),
        )
        predicted: dict[str, object] = {
            "query_results": [{"F": "a"}, {"F": "b"}]
        }
        assert verify_results_from_tool_steps(predicted, steps) is True
