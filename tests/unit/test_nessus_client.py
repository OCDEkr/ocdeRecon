"""Nessus REST client tests — full launch/poll/export choreography, no real server.

Uses httpx.MockTransport to simulate the Nessus API so the client's request flow
and polling are exercised offline.
"""

from __future__ import annotations

import httpx

from pentui.core.nessus_client import NessusClient


def _make_client(tmp_state: dict) -> NessusClient:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        if path == "/editor/scan/templates":
            return httpx.Response(200, json={"templates": [{"name": "basic", "uuid": "TPL-1"}]})
        if path == "/scans" and method == "POST":
            return httpx.Response(200, json={"scan": {"id": 42}})
        if path == "/scans/42/launch":
            return httpx.Response(200, json={"scan_uuid": "abc"})
        if path == "/scans/42" and method == "GET":
            tmp_state["polls"] += 1
            status = "completed" if tmp_state["polls"] >= 2 else "running"
            return httpx.Response(200, json={"info": {"status": status}})
        if path == "/scans/42/export" and method == "POST":
            return httpx.Response(200, json={"file": 99})
        if path == "/scans/42/export/99/status":
            return httpx.Response(200, json={"status": "ready"})
        if path == "/scans/42/export/99/download":
            return httpx.Response(200, content=b"<NessusClientData_v2/>")
        return httpx.Response(404, text=f"unexpected {method} {path}")

    http = httpx.AsyncClient(
        base_url="https://localhost:8834", transport=httpx.MockTransport(handler)
    )
    return NessusClient("https://localhost:8834", "ak", "sk", http, poll_interval=0)


async def test_launch_poll_and_export(tmp_path):
    state = {"polls": 0}
    client = _make_client(state)
    try:
        scan_id = await client.launch(["10.0.0.50", "10.0.0.51"], name="pentui test")
        assert scan_id == 42

        statuses: list[str] = []
        final = await client.wait(scan_id, on_status=statuses.append)
        assert final == "completed"
        assert statuses == ["running", "completed"]  # de-duped transitions

        dest = tmp_path / "out.nessus"
        await client.export_nessus(scan_id, dest)
        assert dest.read_bytes() == b"<NessusClientData_v2/>"
    finally:
        await client.aclose()


async def test_api_error_is_raised(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    http = httpx.AsyncClient(
        base_url="https://localhost:8834", transport=httpx.MockTransport(handler)
    )
    client = NessusClient("https://localhost:8834", "ak", "sk", http, poll_interval=0)
    import pytest

    from pentui.core.nessus_client import NessusError

    try:
        with pytest.raises(NessusError):
            await client.launch(["10.0.0.1"], name="x")
    finally:
        await client.aclose()
