"""Runtime context for SABER Az Bridge commands."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .http_client import EndpointConfig, LiveClient
from .state import StateStore


@dataclass(slots=True)
class GlobalOptions:
    """Global Azure CLI-style options."""

    output: str = "json"
    query: str | None = None
    subscription: str | None = None
    only_show_errors: bool = False
    debug: bool = False
    verbose: bool = False
    help: bool = False


class BridgeContext:
    """Per-invocation command context."""

    def __init__(self, globals: GlobalOptions) -> None:
        self.globals = globals
        self.backend = os.environ.get("AZ_BRIDGE_BACKEND", "hybrid").lower()
        self.config_dir = Path(os.environ.get("AZURE_CONFIG_DIR", str(Path.home() / ".azure")))
        initial_path = _optional_path(os.environ.get("AZ_BRIDGE_INITIAL_STATE"))
        base_path = _optional_path(os.environ.get("AZ_BRIDGE_BASE_INFRASTRUCTURE"))
        if base_path is None and initial_path is not None:
            candidates = [
                initial_path.parent / "base_infrastructure.yaml",
                initial_path.parent.parent / "base_infrastructure.yaml",
            ]
            base_path = next((candidate for candidate in candidates if candidate.exists()), None)
        state_path = Path(os.environ.get("AZ_BRIDGE_STATE", "/tmp/saber_az_bridge_state.json"))
        self.state_store = StateStore(state_path=state_path, initial_path=initial_path, base_path=base_path)
        self.live = LiveClient(
            EndpointConfig(
                aad_url=os.environ.get("AZ_BRIDGE_AAD_URL", "http://azure-ad:8080").rstrip("/"),
                arm_url=os.environ.get("AZ_BRIDGE_ARM_URL", "https://arm-api:443").rstrip("/"),
                keyvault_url=os.environ.get("AZ_BRIDGE_KEYVAULT_URL", "https://keyvault:443").rstrip("/"),
                imds_url=os.environ.get("AZ_BRIDGE_IMDS_URL", "http://imds:80").rstrip("/"),
                eventgrid_url=os.environ.get("AZ_BRIDGE_EVENTGRID_URL", "http://eventgrid:4000").rstrip("/"),
                functions_url=os.environ.get("AZ_BRIDGE_FUNCTIONS_URL", "http://azure-functions:7071").rstrip("/"),
                storage_blob_url=os.environ.get("AZ_BRIDGE_STORAGE_BLOB_URL", "http://azure-blob-storage:10000").rstrip(
                    "/"
                ),
                exchange_url=os.environ.get("AZ_BRIDGE_EXCHANGE_URL", "https://exchange-online:443").rstrip("/"),
            ),
            self.backend,
        )

    @property
    def profile_path(self) -> Path:
        return self.config_dir / "saber_az_bridge_profile.json"

    def load_profile(self) -> dict[str, Any]:
        """Load local account/token profile."""

        if not self.profile_path.exists():
            return {}
        try:
            data = json.loads(self.profile_path.read_text())
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def save_profile(self, profile: dict[str, Any]) -> None:
        """Persist local account/token profile."""

        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.profile_path.write_text(json.dumps(profile, indent=2))

    def clear_profile(self) -> None:
        """Remove local account/token profile."""

        if self.profile_path.exists():
            self.profile_path.unlink()


def _optional_path(value: str | None) -> Path | None:
    if not value:
        return None
    path = Path(value)
    return path if path.exists() else path


def namespace_from_options(options: dict[str, Any]) -> SimpleNamespace:
    """Convert parsed option mapping to an object with attributes."""

    return SimpleNamespace(**options)
