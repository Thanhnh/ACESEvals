"""Small HTTP client wrapper for live SABER mock endpoints."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import requests

from .errors import fail


@dataclass(slots=True)
class EndpointConfig:
    """Runtime endpoint configuration."""

    aad_url: str
    arm_url: str
    keyvault_url: str
    imds_url: str
    eventgrid_url: str
    functions_url: str
    storage_blob_url: str
    exchange_url: str = "https://exchange-online:443"


class LiveClient:
    """HTTP helper that can fail loudly in live-only mode."""

    def __init__(self, endpoints: EndpointConfig, backend: str) -> None:
        self.endpoints = endpoints
        self.backend = backend
        # Build allowlist from configured endpoint hostnames
        self._allowed_origins: set[str] = set()
        for field in (
            endpoints.aad_url, endpoints.arm_url, endpoints.keyvault_url,
            endpoints.imds_url, endpoints.eventgrid_url, endpoints.functions_url,
            endpoints.storage_blob_url, endpoints.exchange_url,
        ):
            parsed = urlparse(field)
            self._allowed_origins.add(f"{parsed.scheme}://{parsed.netloc}")

    @property
    def live_required(self) -> bool:
        return self.backend == "live"

    def _is_url_allowed(self, url: str) -> bool:
        """Check URL targets a known mock endpoint or the sim Docker subnet."""
        import ipaddress

        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        if hostname == "localhost":
            return True
        try:
            ip = ipaddress.ip_address(hostname)
        except ValueError:
            ip = None
        if ip is not None and (ip.is_loopback or ip in ipaddress.ip_network("172.30.0.0/16")):
            return True

        origin = f"{parsed.scheme}://{parsed.netloc}"
        return origin in self._allowed_origins

    def request_json(
        self,
        method: str,
        url: str,
        *,
        token: str | None = None,
        timeout: int = 5,
        **kwargs: Any,
    ) -> Any | None:
        """Return JSON from a live mock endpoint, or ``None`` in hybrid mode if unavailable."""

        if not self._is_url_allowed(url):
            fail(f"SSRF blocked: {url} is not a known mock endpoint")
            return None

        headers = dict(kwargs.pop("headers", {}) or {})
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            response = requests.request(method, url, headers=headers, timeout=timeout, verify=False, **kwargs)
        except requests.RequestException as exc:
            if self.live_required:
                fail(f"Live mock endpoint unavailable: {url} ({exc})")
            return None
        if response.status_code >= 400:
            if self.live_required:
                fail(f"Live mock endpoint returned HTTP {response.status_code}: {response.text[:300]}")
            return None
        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text
