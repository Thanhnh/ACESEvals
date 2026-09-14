"""In-memory process tree for the Windows endpoint mock.

Tracks parent-child relationships, assigns PIDs, and supports lookup by
PID or process name.  All operations are thread-safe.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Optional


@dataclass(frozen=True)
class ProcessInfo:
    """Immutable record of a spawned process."""

    pid: int
    parent_pid: int
    file_name: str
    command_line: str
    user: str
    sha256: str | None = None
    folder_path: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True)
class InjectionInfo:
    """Record of a process injection event."""

    source_pid: int
    target_pid: int
    technique: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))


class ProcessTree:
    """In-memory process tree with auto-incrementing PIDs.

    Designed to be Proxmox-upgrade-ready: all state is accessible via
    semantic queries (``find_by_name``, ``get_process``) rather than
    direct dict access.
    """

    def __init__(
        self,
        hostname: str,
        domain: str,
        device_id: str,
        machine_sid: str,
        start_pid: int = 1000,
    ) -> None:
        self.hostname = hostname
        self.domain = domain
        self.device_id = device_id
        self.machine_sid = machine_sid
        self._next_pid = start_pid
        self._processes: dict[int, ProcessInfo] = {}
        self._injections: list[InjectionInfo] = []
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # Core operations
    # ------------------------------------------------------------------

    def spawn(
        self,
        file_name: str,
        command_line: str,
        parent_process_name: str | None,
        user: str,
        sha256: str | None = None,
        folder_path: str | None = None,
    ) -> ProcessInfo:
        """Create a new process.  Resolves *parent_process_name* to a PID."""
        with self._lock:
            parent_pid = self.find_by_name(parent_process_name) if parent_process_name else 0
            pid = self._next_pid
            self._next_pid += 1
            info = ProcessInfo(
                pid=pid,
                parent_pid=parent_pid,
                file_name=file_name,
                command_line=command_line,
                user=user,
                sha256=sha256,
                folder_path=folder_path,
            )
            self._processes[pid] = info
            return info

    def inject(self, source_pid: int, target_pid: int, technique: str) -> InjectionInfo:
        """Record a process injection event."""
        with self._lock:
            info = InjectionInfo(
                source_pid=source_pid,
                target_pid=target_pid,
                technique=technique,
            )
            self._injections.append(info)
            return info

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def get_process(self, pid: int) -> Optional[ProcessInfo]:
        """Return process info by PID, or ``None``."""
        return self._processes.get(pid)

    def find_by_name(self, name: str) -> int:
        """Return the PID of the *most recently spawned* process matching
        *name* (case-insensitive).  Returns ``0`` if not found."""
        if not name:
            return 0
        name_lower = name.lower()
        with self._lock:
            # Walk in reverse insertion order (dict is ordered in Python 3.7+)
            for pid in reversed(list(self._processes)):
                if self._processes[pid].file_name.lower() == name_lower:
                    return pid
        return 0

    def all_processes(self) -> list[ProcessInfo]:
        """Return a snapshot of all processes (newest first)."""
        with self._lock:
            return list(reversed(self._processes.values()))

    def all_injections(self) -> list[InjectionInfo]:
        """Return a snapshot of all injection events."""
        with self._lock:
            return list(self._injections)
