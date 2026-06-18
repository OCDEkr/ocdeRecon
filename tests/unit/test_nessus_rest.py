"""Phase C: Nessus config, RestRunner, and an end-to-end workflow scan.

Uses a fake Nessus client (no real server) injected via the RestRunner client
factory, so the engine's REST path is exercised exactly like the process path.
"""

from __future__ import annotations

from pathlib import Path

from pentui.config import AppConfig
from pentui.core.manifest import ToolKind, ToolManifest
from pentui.core.models import Severity
from pentui.core.registry import PACKAGED_TOOLS_DIR, ToolRegistry, build_registry
from pentui.core.runner import RestRunner, RunRequest, get_runner
from pentui.core.workflow import WorkflowDefinition, WorkflowEngine
from pentui.persistence.engagement import open_engagement
from pentui.persistence.repositories import FindingRepository, HostRepository, TargetRepository

from .test_nessus_parser import SAMPLE_NESSUS


class FakeClient:
    """Stands in for NessusClient: records targets, writes the sample export."""

    def __init__(self, sample: str = SAMPLE_NESSUS) -> None:
        self.sample = sample
        self.targets: list[str] = []
        self.name: str | None = None
        self.settings: dict[str, str] | None = None
        self.stopped = False

    async def launch(self, targets, name, settings=None):  # noqa: ANN001
        self.targets = list(targets)
        self.name = name
        self.settings = settings
        return 7

    async def wait(self, scan_id, on_status=None):  # noqa: ANN001
        if on_status:
            on_status("running")
            on_status("completed")
        return "completed"

    async def export_nessus(self, scan_id, dest):  # noqa: ANN001
        Path(dest).write_text(self.sample)

    async def stop(self, scan_id):  # noqa: ANN001
        self.stopped = True

    async def aclose(self):
        pass


def _config(tmp_path: Path, *, keys: bool = True) -> AppConfig:
    config = AppConfig(data_dir=tmp_path / "data", config_dir=tmp_path / "config")
    config.ensure_dirs()
    if keys:
        config.set_nessus_settings(access_key="ak", secret_key="sk")
    return config


# -- config ---------------------------------------------------------------- #
def test_nessus_settings_default_and_round_trip(tmp_path, monkeypatch):
    for var in ("NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    config = _config(tmp_path, keys=False)
    s = config.nessus_settings()
    assert s.url == "https://localhost:8834" and not s.configured

    config.set_nessus_settings(access_key="A", secret_key="B")
    s = config.nessus_settings()
    assert s.configured and s.access_key == "A" and s.secret_key == "B"


def test_nessus_env_overrides_settings(tmp_path, monkeypatch):
    config = _config(tmp_path, keys=True)
    monkeypatch.setenv("NESSUS_URL", "https://10.0.0.9:8834")
    monkeypatch.setenv("NESSUS_ACCESS_KEY", "envA")
    s = config.nessus_settings()
    assert s.url == "https://10.0.0.9:8834" and s.access_key == "envA"


# -- RestRunner ------------------------------------------------------------ #
def _rest_req(tmp_path: Path, **overrides) -> RunRequest:  # noqa: ANN003
    kw = {
        "manifest": ToolManifest(name="nessus", binary="nessuscli", kind=ToolKind.REST),
        "profile": None,
        "options": {},
        "extra_args": [],
        "targets": ["10.0.0.50"],
        "scan_dir": tmp_path / "scan",
        "sudo": False,
    }
    kw.update(overrides)
    return RunRequest(**kw)


async def test_rest_runner_runs_scan_and_writes_artifact(tmp_path):
    config = _config(tmp_path)
    fake = FakeClient()
    runner = RestRunner(config, client_factory=lambda _s: fake)
    req = _rest_req(tmp_path)
    plan = runner.prepare(req)
    # The exported .nessus is named after the scanned target, not a generic name.
    assert plan.artifact_path.endswith("10.0.0.50.nessus")

    lines: list[str] = []
    result = await runner.execute(req, plan, on_line=lines.append, on_marker=lambda _m: None)

    assert result.ok and result.exit_code == 0
    assert fake.targets == ["10.0.0.50"]
    assert Path(plan.artifact_path).read_text() == SAMPLE_NESSUS
    assert any("launched Nessus scan 7" in line for line in lines)


async def test_rest_runner_passes_scan_name_and_settings(tmp_path):
    config = _config(tmp_path)
    fake = FakeClient()
    runner = RestRunner(config, client_factory=lambda _s: fake)
    # A custom scan name and a bool option that maps to a Nessus yes/no preference.
    req = _rest_req(
        tmp_path,
        scan_name="ACME Internal District Office",
        options={"test_local_nessus_host": False},
    )
    await runner.execute(
        req, runner.prepare(req), on_line=lambda _l: None, on_marker=lambda _m: None
    )
    assert fake.name == "ACME Internal District Office"
    assert fake.settings == {"test_local_nessus_host": "no"}


async def test_rest_runner_defaults_scan_name(tmp_path):
    config = _config(tmp_path)
    fake = FakeClient()
    runner = RestRunner(config, client_factory=lambda _s: fake)
    req = _rest_req(tmp_path)  # no scan_name
    await runner.execute(
        req, runner.prepare(req), on_line=lambda _l: None, on_marker=lambda _m: None
    )
    assert fake.name == f"pentui {req.scan_dir.name}"
    assert fake.settings == {}


async def test_rest_runner_without_keys_fails_cleanly(tmp_path, monkeypatch):
    for var in ("NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    config = _config(tmp_path, keys=False)
    runner = RestRunner(config, client_factory=lambda _s: FakeClient())
    req = _rest_req(tmp_path)
    markers: list[str] = []
    result = await runner.execute(
        req, runner.prepare(req), on_line=lambda _line: None, on_marker=markers.append
    )
    assert not result.ok
    assert any("API keys" in m for m in markers)


def test_get_runner_dispatches_rest_with_config(tmp_path):
    config = _config(tmp_path)
    rest = ToolManifest(name="nessus", binary="x", kind=ToolKind.REST)
    assert isinstance(get_runner(rest, config), RestRunner)


# -- end-to-end workflow --------------------------------------------------- #
async def test_workflow_nessus_scan_persists_findings(tmp_path, monkeypatch):
    config = _config(tmp_path)
    tools = tmp_path / "tools"
    tools.mkdir()
    (tools / "nessus.yaml").write_text(
        "name: nessus\nkind: rest\nbinary: nessuscli\n"
        "target: {mode: append}\noutput: {parser: nessus}\n"
    )
    registry = ToolRegistry()
    registry.load_dir(tools)
    eng = open_engagement(config, "wf")
    TargetRepository(eng.conn).create(eng.project_id, "10.0.0.50")

    # Inject the fake client into the runner the engine builds.
    monkeypatch.setattr("pentui.core.runner._make_nessus_client", lambda _s: FakeClient())

    wf = WorkflowDefinition.model_validate(
        {
            "name": "nessus-scan",
            "steps": [{"id": "scan", "tool": "nessus", "targets": {"from": "project"}}],
        }
    )
    await WorkflowEngine(eng, registry, config, unattended=True).run(wf)

    hosts = HostRepository(eng.conn).list_for_project(eng.project_id)
    assert [h.ip for h in hosts] == ["10.0.0.50"]
    findings = FindingRepository(eng.conn).list_for_project(eng.project_id)
    assert any(f.source_tool == "nessus" and f.severity is Severity.HIGH for f in findings)


def test_shipped_nessus_manifest_is_rest():
    nessus = build_registry().get("nessus")
    assert nessus is not None and nessus.kind is ToolKind.REST
    assert nessus.output.parser == "nessus"
    # the management CLI is preserved separately and is a normal process tool
    cli = ToolRegistry()
    cli.load_dir(PACKAGED_TOOLS_DIR)
    assert cli.get("nessuscli") is not None and cli.get("nessuscli").kind is ToolKind.PROCESS
