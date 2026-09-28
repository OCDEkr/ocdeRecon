"""Nessus REST client tests — full launch/poll/export choreography, no real server.

Uses httpx.MockTransport to simulate the Nessus API so the client's request flow
and polling are exercised offline.
"""

from __future__ import annotations

import httpx
import pytest

from pentui.core.nessus_client import NessusClient, NessusError


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


async def test_launch_merges_settings_into_body(tmp_path):
    """Extra settings (e.g. test_local_nessus_host) land in the POST /scans body,
    without clobbering the core name/text_targets/enabled fields."""
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/editor/scan/templates":
            return httpx.Response(200, json={"templates": [{"name": "basic", "uuid": "TPL-1"}]})
        if path == "/scans" and request.method == "POST":
            import json

            captured.update(json.loads(request.content)["settings"])
            return httpx.Response(200, json={"scan": {"id": 42}})
        if path == "/scans/42/launch":
            return httpx.Response(200, json={})
        return httpx.Response(404, text=f"unexpected {request.method} {path}")

    http = httpx.AsyncClient(
        base_url="https://localhost:8834", transport=httpx.MockTransport(handler)
    )
    client = NessusClient("https://localhost:8834", "ak", "sk", http, poll_interval=0)
    try:
        await client.launch(
            ["10.0.0.50"],
            name="ACME Internal District Office",
            settings={"test_local_nessus_host": "no"},
        )
    finally:
        await client.aclose()
    assert captured["test_local_nessus_host"] == "no"
    assert captured["name"] == "ACME Internal District Office"
    assert captured["text_targets"] == "10.0.0.50"
    assert captured["enabled"] is False


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


async def test_transport_error_names_the_exception():
    # httpx timeouts stringify to "" — the error must still say what happened.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/editor/scan/templates":
            return httpx.Response(200, json={"templates": [{"name": "basic", "uuid": "T"}]})
        raise httpx.ReadTimeout("", request=request)

    http = httpx.AsyncClient(
        base_url="https://localhost:8834", transport=httpx.MockTransport(handler)
    )
    client = NessusClient("https://localhost:8834", "ak", "sk", http, poll_interval=0)
    try:
        with pytest.raises(NessusError, match=r"POST /scans: ReadTimeout .*in time"):
            await client.launch(["10.0.0.50"], name="t")
    finally:
        await client.aclose()


_JS = 'x={key:"getApiToken",value:function(){return"1A23B8A6-F035-43BB-BA0B-9B75EC38E80D"}}'


def _gated_client(seen: list[httpx.Request], *, api_token: str | None = None) -> NessusClient:
    """Mimic Nessus Professional: scan control is 412 unless X-API-Token is sent."""

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/nessus6.js":
            return httpx.Response(200, text=_JS)
        if request.url.path == "/editor/scan/templates":
            return httpx.Response(200, json={"templates": [{"name": "basic", "uuid": "T"}]})
        if "X-API-Token" not in request.headers:
            return httpx.Response(412, json={"error": "API is not available"})
        if request.url.path == "/scans":
            return httpx.Response(200, json={"scan": {"id": 7}})
        return httpx.Response(200, json={})

    http = httpx.AsyncClient(
        base_url="https://localhost:8834", transport=httpx.MockTransport(handler)
    )
    return NessusClient(
        "https://localhost:8834", "ak", "sk", http, api_token=api_token, poll_interval=0
    )


async def test_web_ui_api_token_is_discovered_and_sent():
    seen: list[httpx.Request] = []
    client = _gated_client(seen)
    try:
        assert await client.launch(["10.0.0.50"], name="t") == 7
    finally:
        await client.aclose()
    assert [r.url.path for r in seen].count("/nessus6.js") == 1  # fetched once
    api_calls = [r for r in seen if r.url.path != "/nessus6.js"]
    assert all(
        r.headers["X-API-Token"] == "1A23B8A6-F035-43BB-BA0B-9B75EC38E80D" for r in api_calls
    )
    assert all(r.headers["X-ApiKeys"] == "accessKey=ak; secretKey=sk" for r in api_calls)


async def test_explicit_api_token_skips_discovery():
    seen: list[httpx.Request] = []
    client = _gated_client(seen, api_token="FEEDFACE-0000-0000-0000-000000000000")
    try:
        await client.launch(["10.0.0.50"], name="t")
    finally:
        await client.aclose()
    assert "/nessus6.js" not in [r.url.path for r in seen]
    assert seen[-1].headers["X-API-Token"] == "FEEDFACE-0000-0000-0000-000000000000"


async def test_412_without_token_explains_the_pro_gate():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/editor/scan/templates":
            return httpx.Response(200, json={"templates": [{"name": "basic", "uuid": "T"}]})
        if request.url.path == "/nessus6.js":
            return httpx.Response(404)
        return httpx.Response(412, json={"error": "API is not available"})

    http = httpx.AsyncClient(
        base_url="https://localhost:8834", transport=httpx.MockTransport(handler)
    )
    client = NessusClient("https://localhost:8834", "ak", "sk", http, poll_interval=0)
    try:
        with pytest.raises(NessusError, match=r"HTTP 412 .*NESSUS_API_TOKEN"):
            await client.launch(["10.0.0.50"], name="t")
    finally:
        await client.aclose()
