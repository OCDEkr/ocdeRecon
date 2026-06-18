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


def test_packaged_engagement_recon_loads_and_validates():
    wf = load_workflow(PACKAGED_WORKFLOWS_DIR / "engagement-recon.yaml")
    assert wf.name == "engagement-recon"
    ids = {s.id for s in wf.steps}
    assert ids == {"discover", "vuln-scan", "scan", "shots", "dc-identify", "smb-sweep"}
    shots = next(s for s in wf.steps if s.id == "shots")
    assert shots.file_from is not None and shots.file_from.step == "scan"
    # gowitness screenshots only open web services, persisting shots + DB.
    assert shots.options.get("--open-only") is True
    assert shots.options.get("--write-screenshots") is True
    # The nmap scan runs at T4 (workflow steps don't inherit the manifest default).
    scan = next(s for s in wf.steps if s.id == "scan")
    assert scan.options.get("-T") == "4"
    # Nessus branches off masscan (parallel to nmap), names the scan, and skips
    # the local host. Its only dependency is `discover`, not `scan`.
    vuln = next(s for s in wf.steps if s.id == "vuln-scan")
    assert vuln.after == ["discover"]
    assert vuln.scan_name == "{engagement} Internal District Office"
    assert vuln.options.get("test_local_nessus_host") is False


def test_workflow_registry_has_engagement_recon():
    registry = build_workflow_registry()
    assert "engagement-recon" in registry.names()
    assert registry.errors == []
