"""Tool registry discovery tests."""

from __future__ import annotations

from pentui.core.registry import ToolRegistry, build_registry


def test_packaged_registry_has_nmap():
    registry = build_registry()
    assert "nmap" in registry.names()
    assert registry.get("nmap").binary == "nmap"
    assert registry.errors == []


def test_packaged_tools_all_load():
    registry = build_registry()
    expected = {
        "nmap", "gowitness", "nxc", "responder", "ntlmrelayx", "mitm6", "nessus",
        "masscan", "nslookup",
    }
    assert expected <= set(registry.names())
    assert registry.errors == []
    # masscan reuses the nmap XML parser and always needs root.
    masscan = registry.get("masscan")
    assert masscan.requires_root is True
    assert masscan.output.parser == "nmap_xml"


def test_user_dir_overrides_and_bad_manifest_recorded(tmp_path):
    # A user manifest that overrides nmap's description.
    (tmp_path / "nmap.yaml").write_text(
        "name: nmap\nbinary: nmap\ndescription: custom\n"
    )
    # A broken manifest that must be skipped, not fatal.
    (tmp_path / "broken.yaml").write_text("options: [oops]\n")

    registry = build_registry(tmp_path)
    assert registry.get("nmap").description == "custom"
    assert len(registry.errors) == 1
    assert "broken.yaml" in registry.errors[0]


def test_missing_dir_is_noop():
    registry = ToolRegistry()
    registry.load_dir("/nonexistent/path/xyz")
    assert registry.names() == []
