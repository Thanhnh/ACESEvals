"""Output formatting helpers for SABER Az Bridge."""

from __future__ import annotations

import json
from typing import Any

try:
    import jmespath
except ImportError:  # pragma: no cover - depends on container image.
    jmespath = None

try:
    import yaml
except ImportError:  # pragma: no cover - depends on container image.
    yaml = None


def apply_query(data: Any, query: str | None) -> Any:
    """Apply a JMESPath query, matching Azure CLI behavior closely enough for scripts."""

    if not query:
        return data
    if jmespath is None:
        return _fallback_query(data, query)
    try:
        return jmespath.search(query, data)
    except jmespath.exceptions.JMESPathError:
        return data


def format_output(data: Any, output_format: str, query: str | None = None) -> str:
    """Format command output according to Azure CLI-style ``--output``."""

    data = apply_query(data, query)
    if output_format == "none" or data is None:
        return ""
    if output_format in {"json", "jsonc"}:
        return json.dumps(data, indent=2)
    if output_format in {"yaml", "yamlc"}:
        if yaml is None:
            raise RuntimeError("YAML output requires the 'PyYAML' Python package.")
        return yaml.safe_dump(data, sort_keys=False).rstrip()
    if output_format == "tsv":
        return _format_tsv(data)
    if output_format == "table":
        return _format_table(data)
    return str(data)


def _fallback_query(data: Any, query: str) -> Any:
    query = query.strip()
    if query.startswith("[]."):
        path = query[3:]
        if isinstance(data, list):
            return [_select_path(item, path) for item in data]
        return []
    return _select_path(data, query)


def _select_path(data: Any, path: str) -> Any:
    current = data
    if not path:
        return current
    for part in path.split("."):
        if part == "[]":
            if isinstance(current, list):
                current = list(current)
                continue
            return None
        if isinstance(current, dict):
            current = current.get(part)
            continue
        if isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if 0 <= index < len(current) else None
            continue
        return None
    return current


def _format_tsv(data: Any) -> str:
    if isinstance(data, list):
        return "\n".join(_format_tsv(item) for item in data)
    if isinstance(data, dict):
        return "\t".join("" if value is None else str(value) for value in data.values())
    return "" if data is None else str(data)


def _format_table(data: Any) -> str:
    rows = data if isinstance(data, list) else [data]
    if not rows or not all(isinstance(row, dict) for row in rows):
        return str(data)
    keys: list[str] = []
    for row in rows:
        for key, value in row.items():
            if key not in keys and not isinstance(value, (dict, list)):
                keys.append(key)
    if not keys:
        return str(data)
    values = [["" if row.get(key) is None else str(row.get(key)) for key in keys] for row in rows]
    widths = [max(len(key), *(len(row[index]) for row in values)) for index, key in enumerate(keys)]
    header = "  ".join(key.ljust(widths[index]) for index, key in enumerate(keys))
    separator = "  ".join("-" * widths[index] for index in range(len(keys)))
    body = ["  ".join(row[index].ljust(widths[index]) for index in range(len(keys))) for row in values]
    return "\n".join([header, separator, *body])
