"""Workflow schema, DAG validation, loader, and registry tests."""

from __future__ import annotations

import pytest

from pentui.core.query import Materializer
from pentui.core.workflow import (
    PACKAGED_WORKFLOWS_DIR,
    WorkflowDefinition,
    WorkflowError,
    build_workflow_registry,
    load_workflow,
    save_workflow,
    topological_order,
)


def _wf(steps: list[dict]) -> WorkflowDefinition:
    return WorkflowDefinition.model_validate({"name": "t", "steps": steps})


def test_topological_order_respects_dependencies():
    wf = _wf([
        {"id": "a", "tool": "x"},
        {"id": "b", "tool": "x", "after": ["a"]},
        {"id": "c", "tool": "x", "after": ["a"]},
        {"id": "d", "tool": "x", "after": ["b", "c"]},
    ])
    order = topological_order(wf.steps)
    assert order.index("a") < order.index("b") < order.index("d")
    assert order.index("a") < order.index("c") < order.index("d")


def test_cycle_is_rejected():
    with pytest.raises(WorkflowError):
        WorkflowDefinition.model_validate(
            {"name": "t", "steps": [
                {"id": "a", "tool": "x", "after": ["b"]},
                {"id": "b", "tool": "x", "after": ["a"]},
            ]}
        )


def test_unknown_dependency_rejected():
    with pytest.raises(ValueError):
        _wf([{"id": "a", "tool": "x", "after": ["ghost"]}])


def test_duplicate_ids_rejected():
    with pytest.raises(ValueError):
        _wf([{"id": "a", "tool": "x"}, {"id": "a", "tool": "y"}])


def test_packaged_web_recon_loads_and_validates():
    wf = load_workflow(PACKAGED_WORKFLOWS_DIR / "web-recon.yaml")
    assert wf.name == "web-recon"
    ids = {s.id for s in wf.steps}
    assert ids == {"discover", "web-shots", "service-scan"}
    shots = next(s for s in wf.steps if s.id == "web-shots")
    assert shots.input is not None
    assert shots.input.as_.value == "target_urls"
    service = next(s for s in wf.steps if s.id == "service-scan")
    assert service.gate is True


def test_workflow_registry_has_web_recon():
    registry = build_workflow_registry()
    assert "web-recon" in registry.names()
    assert registry.errors == []


def test_save_workflow_round_trips(tmp_path):
    wf = WorkflowDefinition.model_validate(
        {
            "name": "rt",
            "description": "round trip",
            "steps": [
                {"id": "discover", "tool": "nmap", "profile": "Quick",
                 "extra_args": ["--top-ports", "100"], "targets": {"from": "project"}},
                {"id": "shots", "tool": "gowitness", "after": ["discover"], "gate": True,
                 "input": {"from": "hosts", "where": {"port_open_in": [80, 443]},
                           "as": "target_urls"}},
            ],
        }
    )
    loaded = load_workflow(save_workflow(wf, tmp_path / "rt.yaml"))
    assert loaded.name == "rt"
    assert [s.id for s in loaded.steps] == ["discover", "shots"]
    assert loaded.steps[0].targets.from_ == "project"
    assert loaded.steps[0].extra_args == ["--top-ports", "100"]
    shots = loaded.steps[1]
    assert shots.after == ["discover"]
    assert shots.gate is True
    assert shots.input.as_ is Materializer.TARGET_URLS
    assert shots.input.where.port_open_in == [80, 443]
