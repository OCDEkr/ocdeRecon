"""Async client for the local Nessus REST API (PROJECT.md §14, Phase C).

Talks to a Nessus instance (default ``https://localhost:8834``) over its native
REST API with API-key auth (``X-ApiKeys``), plus the web UI's ``X-API-Token``
(scraped from ``/nessus6.js``) that Nessus Professional requires before it lets
API keys create/launch/stop scans. Scanning runs entirely on the local
Nessus engine — nothing is sent to Tenable's cloud. The self-signed localhost
certificate means TLS verification is disabled by design.

Core-only and UI-free: the workflow engine's RestRunner drives it, streaming
status through a callback. Poll loops use ``asyncio.sleep`` so they never block
the event loop, and cancellation propagates so a stopped scan is stopped server
-side too. The ``httpx.AsyncClient`` is injected, which keeps it fully testable
with ``httpx.MockTransport`` (no real Nessus needed).
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import httpx

#: Scan statuses that mean the run has stopped (success or otherwise).
TERMINAL_STATUSES = frozenset(
    {"completed", "canceled", "cancelled", "aborted", "empty", "imported"}
)
#: Statuses we treat as a usable result worth exporting/parsing.
OK_STATUSES = frozenset({"completed", "imported"})

#: Scan-template short names to prefer, best first (Basic Network Scan, etc.).
_PREFERRED_TEMPLATES = ("basic", "advanced", "discovery")

#: The web UI's API token as embedded in /nessus6.js, e.g.
#: ``{key:"getApiToken",value:function(){return"1A23B8A6-...-9B75EC38E80D"}}``.
_API_TOKEN_RE = re.compile(
    r'getApiToken"\s*,\s*value\s*:\s*function\s*\(\)\s*\{\s*return\s*"([0-9A-Fa-f-]{36})"'
)
_NO_TOKEN_HINT = (
    "Nessus Professional blocks API scan control without the web UI token; "
    "set NESSUS_API_TOKEN or 'api_token' under 'nessus' in settings.json"
)


class NessusError(Exception):
    """A Nessus API call failed or returned an unexpected response."""


class NessusClient:
    """Minimal Nessus REST client: launch a scan, poll it, export the .nessus."""

    def __init__(
        self,
        url: str,
        access_key: str,
        secret_key: str,
        http: httpx.AsyncClient,
        *,
        api_token: str | None = None,
        poll_interval: float = 5.0,
    ) -> None:
        self._http = http
        self._headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}
        self._api_token = api_token
        self._token_resolved = False
        self._poll_interval = poll_interval

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- HTTP helpers ------------------------------------------------------ #
    async def _resolve_api_token(self) -> None:
        """Attach the web UI's ``X-API-Token`` (once, before the first call).

        Nessus Professional answers scan create/launch/stop with
        ``412 API is not available`` for API-key requests unless they also carry
        the token its own web UI sends, which is embedded in ``/nessus6.js``.
        Discovery is best-effort: editions that don't gate the API (Manager)
        work without it, so a missing token is not an error.
        """
        if self._token_resolved:
            return
        self._token_resolved = True
        if self._api_token is None:
            with contextlib.suppress(httpx.HTTPError):
                resp = await self._http.get("/nessus6.js")
                if resp.status_code == 200:
                    match = _API_TOKEN_RE.search(resp.text)
                    self._api_token = match.group(1) if match else None
        if self._api_token:
            self._headers["X-API-Token"] = self._api_token

    async def _request(self, method: str, path: str, **kw: Any) -> httpx.Response:
        await self._resolve_api_token()
        try:
            resp = await self._http.request(method, path, headers=self._headers, **kw)
        except httpx.HTTPError as exc:
            # Transport errors (timeouts, dropped connections) often stringify
            # to "" — always name the exception so the failure is diagnosable.
            detail = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
            if isinstance(exc, httpx.TimeoutException):
                detail += " (Nessus did not answer in time — busy or compiling plugins?)"
            elif not self._api_token:
                # Nessus Pro sends its 412 and drops the connection, which
                # surfaces as a ReadError rather than a status code.
                detail += f" ({_NO_TOKEN_HINT})"
            raise NessusError(f"{method} {path}: {detail}") from exc
        if resp.status_code >= 400:
            msg = f"{method} {path}: HTTP {resp.status_code} {resp.text[:200]}"
            if resp.status_code == 412:
                msg += f" ({_NO_TOKEN_HINT})"
            raise NessusError(msg)
        return resp

    async def _json(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        resp = await self._request(method, path, **kw)
        try:
            data = resp.json()
        except ValueError as exc:
            raise NessusError(f"{method} {path}: invalid JSON response") from exc
        return data if isinstance(data, dict) else {}

    # -- scan lifecycle ---------------------------------------------------- #
    async def _template_uuid(self) -> str:
        data = await self._json("GET", "/editor/scan/templates")
        templates = data.get("templates") or []
        by_name = {t.get("name"): t.get("uuid") for t in templates if isinstance(t, dict)}
        for name in _PREFERRED_TEMPLATES:
            if by_name.get(name):
                return str(by_name[name])
        if templates and isinstance(templates[0], dict) and templates[0].get("uuid"):
            return str(templates[0]["uuid"])
        raise NessusError("no scan templates available on the Nessus server")

    async def launch(
        self, targets: Iterable[str], name: str, settings: dict[str, str] | None = None
    ) -> int:
        """Create a scan over ``targets`` and launch it; returns the scan id.

        ``settings`` adds scan-policy preferences (e.g.
        ``{"test_local_nessus_host": "no"}`` to skip the scanner's own host);
        the core fields below always win over any same-named key.
        """
        text_targets = ",".join(targets)
        if not text_targets:
            raise NessusError("no targets to scan")
        body = {
            "uuid": await self._template_uuid(),
            "settings": {
                **(settings or {}),
                "name": name,
                "text_targets": text_targets,
                "enabled": False,
            },
        }
        created = await self._json("POST", "/scans", json=body)
        scan = created.get("scan") or {}
        scan_id = scan.get("id")
        if scan_id is None:
            raise NessusError("Nessus did not return a scan id")
        await self._request("POST", f"/scans/{scan_id}/launch")
        return int(scan_id)

    async def wait(self, scan_id: int, on_status: Callable[[str], None] | None = None) -> str:
        """Poll until the scan reaches a terminal status; returns that status."""
        last: str | None = None
        while True:
            info = (await self._json("GET", f"/scans/{scan_id}")).get("info") or {}
            status = str(info.get("status") or "unknown")
            if status != last:
                if on_status is not None:
                    on_status(status)
                last = status
            if status in TERMINAL_STATUSES:
                return status
            await asyncio.sleep(self._poll_interval)

    async def export_nessus(self, scan_id: int, dest: str | Path) -> None:
        """Export the scan in ``.nessus`` (nessus_v2 XML) format to ``dest``."""
        started = await self._json("POST", f"/scans/{scan_id}/export", json={"format": "nessus"})
        file_id = started.get("file") or started.get("token")
        if file_id is None:
            raise NessusError("Nessus export did not return a file id")
        while True:
            status = (await self._json("GET", f"/scans/{scan_id}/export/{file_id}/status")).get(
                "status"
            )
            if status == "ready":
                break
            await asyncio.sleep(self._poll_interval)
        resp = await self._request("GET", f"/scans/{scan_id}/export/{file_id}/download")
        path = Path(dest)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(resp.content)

    async def stop(self, scan_id: int) -> None:
        """Best-effort stop (used on cancellation); errors are swallowed."""
        with contextlib.suppress(NessusError):
            await self._request("POST", f"/scans/{scan_id}/stop")
