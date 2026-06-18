"""Severity normalization (core/severity.py)."""

from __future__ import annotations

import pytest

from pentui.core.models import Severity
from pentui.core.severity import (
    max_severity,
    normalize_nse_severity,
    severity_from_cvss,
)


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0.0, Severity.INFO),
        (3.9, Severity.LOW),
        (4.0, Severity.MEDIUM),
        (6.9, Severity.MEDIUM),
        (7.0, Severity.HIGH),
        (8.9, Severity.HIGH),
        (9.0, Severity.CRITICAL),
        (10.0, Severity.CRITICAL),
    ],
)
def test_severity_from_cvss_bands(score, expected):
    assert severity_from_cvss(score) is expected


def test_max_severity_picks_worst():
    assert max_severity(Severity.INFO, Severity.HIGH, Severity.LOW) is Severity.HIGH
    assert max_severity(Severity.UNKNOWN, Severity.INFO) is Severity.INFO
    assert max_severity() is Severity.INFO


def test_informational_script_stays_info():
    assert normalize_nse_severity("ssh-hostkey", "2048 aa:bb:cc") is Severity.INFO
    assert normalize_nse_severity("smb-os-discovery", "OS: Windows") is Severity.INFO


def test_vulnerable_state_line_raises_to_high():
    out = "\n  VULNERABLE:\n  Some weakness\n    State: VULNERABLE\n"
    assert normalize_nse_severity("smb-vuln-regsvc-dos", out) is Severity.HIGH
    # "LIKELY VULNERABLE" also counts.
    assert normalize_nse_severity("http-vuln-x", "State: LIKELY VULNERABLE") is Severity.HIGH


def test_known_high_signal_script_mapped():
    assert normalize_nse_severity("smb-vuln-ms17-010", "") is Severity.CRITICAL
    assert normalize_nse_severity("SSL-Heartbleed", "") is Severity.HIGH  # id is case-insensitive


def test_vulners_cvss_drives_severity():
    out = (
        "cpe:/a:openbsd:openssh:7.4:\n"
        "    CVE-2021-28041   4.6   https://vulners.com/cve/CVE-2021-28041\n"
        "    CVE-2019-6111    9.1   https://vulners.com/cve/CVE-2019-6111\n"
    )
    # Worst CVE (9.1) wins → CRITICAL.
    assert normalize_nse_severity("vulners", out) is Severity.CRITICAL


def test_version_numbers_are_not_mistaken_for_cvss():
    # A bare version string with no CVE anchor must not raise severity.
    assert normalize_nse_severity("http-server-header", "Apache 9.9 banner") is Severity.INFO
