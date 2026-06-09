"""Workflow schema, DAG validation, loader, and registry tests."""

from __future__ import annotations

import pytest

from pentui.core.workflow import (
    PACKAGED_WORKFLOWS_DIR,
    WorkflowDefinition,
    WorkflowError,
    build_workflow_registry,
    load_workflow,
    topological_order,
)


def _wf(steps: list[dict]) -> WorkflowDefinition:
    return WorkflowDefinition.model_validate({"name": "t", "steps": steps})


def test_topological_order_respects_dependencies():
    wf = _wf(
        [
            {"id": "a", "tool": "x"},
            {"id": "b", "tool": "x", "after": ["a"]},
            {"id": "c", "tool": "x", "after": ["a"]},
            {"id": "d", "tool": "x", "after": ["b", "c"]},
        ]
    )
    order = topological_order(wf.steps)
    assert order.index("a") < order.index("b") < order.index("d")
    assert order.index("a") < order.index("c") < order.index("d")


def test_cycle_is_rejected():
    with pytest.raises(WorkflowError):
        WorkflowDefinition.model_validate(
            {
                "name": "t",
                "steps": [
                    {"id": "a", "tool": "x", "after": ["b"]},
                    {"id": "b", "tool": "x", "after": ["a"]},
                ],
            }
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
