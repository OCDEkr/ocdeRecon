"""Manifest schema + loader tests, using the packaged nmap.yaml."""

from __future__ import annotations

import pytest

from pentui.core.manifest import (
    ManifestError,
    OptionType,
    TargetMode,
    load_manifest,
)
from pentui.core.registry import PACKAGED_TOOLS_DIR


def test_load_packaged_nmap_manifest():
    manifest = load_manifest(PACKAGED_TOOLS_DIR / "nmap.yaml")
    assert manifest.name == "nmap"
    assert manifest.binary == "nmap"
    assert manifest.target.mode is TargetMode.APPEND
    assert manifest.output.parser == "nmap_xml"
    assert manifest.output.artifact is not None
    assert manifest.output.artifact.flag == "-oX"

    syn = next(o for o in manifest.options if o.flag == "-sS")
    assert syn.requires_root is True
    assert syn.type is OptionType.BOOL

    timing = next(o for o in manifest.options if o.flag == "-T")
    assert timing.type is OptionType.CHOICE
    assert timing.attached is True
    assert timing.default == "4"

    ports = next(o for o in manifest.options if o.flag == "-p")
    assert ports.validate_with == "ports"

    assert manifest.profile("Quick") is not None
    assert manifest.profile("Full TCP").requires_root is True


def test_exclude_flag_defaults_none_and_packaged_scanners_set_it():
    # A tool that doesn't declare one (gowitness) has no exclude flag …
    gowitness = load_manifest(PACKAGED_TOOLS_DIR / "gowitness.yaml")
    assert gowitness.exclude_flag is None
    # … while the network scanners declare --excludefile so the engine can inject
    # the engagement-wide exclude file.
    for tool in ("nmap", "masscan"):
        manifest = load_manifest(PACKAGED_TOOLS_DIR / f"{tool}.yaml")
        assert manifest.exclude_flag == "--excludefile"


def test_invalid_yaml_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: x\nbinary: x\noptions: [not-a-mapping]\n")
    with pytest.raises(ManifestError):
        load_manifest(bad)


def test_choice_without_choices_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: t\nbinary: t\noptions:\n  - {flag: '-x', label: X, type: choice}\n")
    with pytest.raises(ManifestError):
        load_manifest(bad)


def test_target_flag_mode_requires_flag(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("name: t\nbinary: t\ntarget: {mode: flag}\n")
    with pytest.raises(ManifestError):
        load_manifest(bad)
