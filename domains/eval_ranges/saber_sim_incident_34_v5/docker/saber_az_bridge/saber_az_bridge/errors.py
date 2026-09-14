"""Azure CLI-style errors for SABER Az Bridge."""

from __future__ import annotations

import sys
from dataclasses import dataclass


@dataclass(slots=True)
class BridgeError(Exception):
    """A controlled CLI error with an exit status."""

    message: str
    code: int = 1


def fail(message: str, code: int = 1) -> None:
    """Raise a controlled CLI error."""

    raise BridgeError(message, code)


def print_error(error: BridgeError) -> None:
    """Print an Azure CLI-like error message."""

    print(f"ERROR: {error.message}", file=sys.stderr)


def require_options(options: object, required: list[tuple[str, str]]) -> None:
    """Validate required parsed options."""

    missing: list[str] = []
    for attr, display in required:
        value = getattr(options, attr, None)
        if value in (None, "", []):
            missing.append(display)
    if missing:
        fail(f"the following arguments are required: {', '.join(missing)}", 2)


def resource_not_found(resource_type: str, name: str, resource_group: str | None = None) -> None:
    """Raise a ResourceNotFound-style error."""

    if resource_group:
        message = (
            f"The Resource '{resource_type}/{name}' under resource group '{resource_group}' was not found. "
            "For more details please go to https://aka.ms/ARMResourceNotFoundFix"
        )
    else:
        message = f"The Resource '{resource_type}/{name}' was not found."
    fail(f"(ResourceNotFound) {message}", 3)


def unsupported_command(parts: tuple[str, ...], commands: set[tuple[str, ...]]) -> None:
    """Raise an Azure CLI-like unsupported command error."""

    for length in range(len(parts) - 1, 0, -1):
        prefix = parts[:length]
        if any(len(command) > length and command[:length] == prefix for command in commands):
            invalid = parts[length]
            fail(
                f"'{invalid}' is not in the 'az {' '.join(prefix)}' command group. See 'az {' '.join(prefix)} --help'."
            )
    fail(f"Unknown command: {' '.join(parts) if parts else 'az'}")
