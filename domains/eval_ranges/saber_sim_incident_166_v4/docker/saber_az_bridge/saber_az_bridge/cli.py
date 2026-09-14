"""Command-line entry point for SABER Az Bridge."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import Any

from .commands import COMMANDS, GROUP_DESCRIPTIONS
from .context import BridgeContext, GlobalOptions, namespace_from_options
from .errors import BridgeError, print_error, unsupported_command
from .output import format_output

CommandHandler = Callable[[Any, dict[str, Any], BridgeContext], Any]

_GLOBAL_VALUE_FLAGS = {
    "--output": "output",
    "-o": "output",
    "--query": "query",
    "--subscription": "subscription",
}
_GLOBAL_BOOL_FLAGS = {
    "--only-show-errors": "only_show_errors",
    "--debug": "debug",
    "--verbose": "verbose",
    "--help": "help",
    "-h": "help",
}
_SHORT_ALIASES = {
    "-g": "resource_group",
    "-n": "name",
    "-l": "location",
    "-u": "username",
    "-p": "password",
    "-s": "subscription",
    "-f": "file",
}
_MULTI_VALUE_FLAGS = {
    "api_permissions",
    "settings",
    "set",
    "secret_permissions",
    "key_permissions",
    "certificate_permissions",
    "source_address_prefixes",
    "source_port_ranges",
    "destination_address_prefixes",
    "destination_port_ranges",
    "address_prefixes",
    "defaults",
}


def main(argv: list[str] | None = None) -> None:
    """Run the SABER Az Bridge CLI."""

    raw_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        globals, argv_without_globals = _parse_global_options(raw_argv)
        if not argv_without_globals:
            if globals.help:
                print(_top_level_help())
                return
            print(_top_level_help())
            return
        if argv_without_globals[0] in {"--version", "-v"}:
            print_version()
            return
        if argv_without_globals[0] in {"--help", "-h"}:
            print(_top_level_help())
            return
        command_tuple, remaining = _find_command(argv_without_globals)
        if command_tuple is None:
            prefix = tuple(_commandish_parts(argv_without_globals))
            if globals.help and prefix and any(command[: len(prefix)] == prefix for command in COMMANDS):
                print(_group_help(prefix))
                return
            unsupported_command(tuple(_commandish_parts(argv_without_globals)), set(COMMANDS))
        if globals.help:
            print(_command_help(command_tuple))
            return
        options = namespace_from_options(_parse_command_options(remaining))
        context = BridgeContext(globals)
        handler = COMMANDS[command_tuple]
        with context.state_store.locked() as state:
            result = handler(options, state, context)
        rendered = format_output(result, globals.output, globals.query)
        if rendered:
            print(rendered)
    except BridgeError as exc:
        print_error(exc)
        sys.exit(exc.code)


def print_version() -> None:
    """Print Azure CLI-like version information."""

    print("azure-cli                         2.60.0")
    print("saber-az-bridge                   0.1.0")
    print("")
    print("SABER Az Bridge mock Azure CLI for SABER-Sim.")


def _parse_global_options(argv: list[str]) -> tuple[GlobalOptions, list[str]]:
    globals = GlobalOptions()
    remaining: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token in _GLOBAL_VALUE_FLAGS:
            attr = _GLOBAL_VALUE_FLAGS[token]
            if index + 1 < len(argv):
                setattr(globals, attr, argv[index + 1])
                index += 2
                continue
        if token.startswith("--output="):
            globals.output = token.split("=", 1)[1]
            index += 1
            continue
        if token.startswith("--query="):
            globals.query = token.split("=", 1)[1]
            index += 1
            continue
        if token in _GLOBAL_BOOL_FLAGS:
            setattr(globals, _GLOBAL_BOOL_FLAGS[token], True)
            index += 1
            continue
        remaining.append(token)
        index += 1
    return globals, remaining


def _find_command(argv: list[str]) -> tuple[tuple[str, ...] | None, list[str]]:
    prefix = _commandish_parts(argv)
    for length in range(len(prefix), 0, -1):
        command = tuple(prefix[:length])
        if command in COMMANDS:
            return command, argv[length:]
    return None, argv


def _commandish_parts(argv: list[str]) -> list[str]:
    parts: list[str] = []
    for token in argv:
        if token.startswith("-"):
            break
        parts.append(token)
    return parts


def _parse_command_options(tokens: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {"_positional": []}
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("--"):
            flag, inline_value = _split_long_flag(token)
            name = flag[2:].replace("-", "_")
            if inline_value is not None:
                _append_or_set(options, name, inline_value)
                index += 1
                continue
            if name in _MULTI_VALUE_FLAGS:
                values: list[str] = []
                index += 1
                while index < len(tokens) and not tokens[index].startswith("-"):
                    values.append(tokens[index])
                    index += 1
                options[name] = values
                continue
            if index + 1 < len(tokens) and not tokens[index + 1].startswith("-"):
                options[name] = tokens[index + 1]
                index += 2
                continue
            options[name] = True
            index += 1
            continue
        if token in _SHORT_ALIASES:
            name = _SHORT_ALIASES[token]
            if index + 1 < len(tokens):
                options[name] = tokens[index + 1]
                index += 2
                continue
        options["_positional"].append(token)
        index += 1
    return options


def _split_long_flag(token: str) -> tuple[str, str | None]:
    if "=" in token:
        flag, value = token.split("=", 1)
        return flag, value
    return token, None


def _append_or_set(options: dict[str, Any], name: str, value: str) -> None:
    if name in _MULTI_VALUE_FLAGS:
        options.setdefault(name, []).append(value)
    else:
        options[name] = value


def _top_level_help() -> str:
    groups = sorted({command[0] for command in COMMANDS})
    lines = ["Usage: az <group> <command> [options]", "", "Supported command groups:"]
    for group in groups:
        lines.append(f"  {group.ljust(14)} {GROUP_DESCRIPTIONS.get(group, '')}")
    return "\n".join(lines)


def _group_help(prefix: tuple[str, ...]) -> str:
    children: dict[str, bool] = {}
    for command in COMMANDS:
        if command[: len(prefix)] != prefix or len(command) <= len(prefix):
            continue
        child = command[len(prefix)]
        children[child] = children.get(child, False) or len(command) > len(prefix) + 1

    lines = [f"Group\n    az {' '.join(prefix)} : SABER Az Bridge supported command group.", ""]
    if children:
        lines.append("Commands:")
        for child, is_group in sorted(children.items()):
            suffix = "command group" if is_group else "command"
            lines.append(f"  {child.ljust(18)} {suffix}")
    return "\n".join(lines)


def _command_help(command: tuple[str, ...]) -> str:
    return f"Command\n    az {' '.join(command)} : SABER Az Bridge supported command."
