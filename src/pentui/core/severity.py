"""Central severity normalization for findings (PROJECT.md §14).

Parsers historically hard-coded a single severity (nmap NSE → ``info``). This
module turns tool-native signals — CVSS base scores, nmap "VULNERABLE" state
lines, and a small table of high-signal NSE script ids — into the unified
:class:`~pentui.core.models.Severity`, so vuln findings carry a meaningful
severity instead of a flat ``info``.

Conservative by design: when nothing matches, the result is ``INFO`` (the old
behaviour), so normalization only ever *raises* a finding's severity from a
recognized signal — it never invents risk from noise.

Core-only and UI-free: pure functions, no I/O.
"""

from __future__ import annotations

import re

from pentui.core.models import Severity

#: Severity rank, lowest → highest, for :func:`max_severity`.
_ORDER: tuple[Severity, ...] = (
    Severity.UNKNOWN,
    Severity.INFO,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
)


def max_severity(*severities: Severity) -> Severity:
    """The most severe of ``severities`` (``INFO`` if none given)."""
    return max(severities, key=_ORDER.index, default=Severity.INFO)


def severity_from_cvss(score: float) -> Severity:
    """Map a CVSS base score (0.0–10.0) to a Severity using the CVSS v3 bands."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


#: NSE scripts whose firing is itself a confirmed, high-risk finding regardless
#: of output text. Keyed by (lowercased) script id. Extend as needs arise.
_NSE_SEVERITY: dict[str, Severity] = {
    "smb-vuln-ms17-010": Severity.CRITICAL,  # EternalBlue
    "smb-vuln-ms08-067": Severity.CRITICAL,
    "smb-vuln-cve-2017-7494": Severity.CRITICAL,  # SambaCry
    "smb-double-pulsar-backdoor": Severity.CRITICAL,
    "http-shellshock": Severity.CRITICAL,
    "rdp-vuln-ms12-020": Severity.HIGH,
    "ssl-heartbleed": Severity.HIGH,
    "ssl-poodle": Severity.MEDIUM,
    "ssl-dh-params": Severity.MEDIUM,
    "ssl-ccs-injection": Severity.MEDIUM,
}

#: nmap's `vuln`-category scripts print a state line when a target is affected.
_VULNERABLE_RE = re.compile(r"\bState:\s*(?:LIKELY\s+)?VULNERABLE\b", re.IGNORECASE)
#: The `vulners` script lists `CVE-YYYY-NNNN  <cvss>  <url>` per finding; pull the
#: scores so the worst CVE drives the severity. Anchored on the CVE id so we never
#: mistake a version string (e.g. "OpenSSH 7.4") for a score.
_VULNERS_RE = re.compile(r"CVE-\d{4}-\d+\s+(\d{1,2}(?:\.\d)?)")


def normalize_nse_severity(script_id: str, output: str | None) -> Severity:
    """Infer a Severity for an NSE script finding from its id and output.

    Takes the most severe of three signals — a `vulners` CVSS score, a
    "VULNERABLE" state line, and the high-signal script table — defaulting to
    ``INFO`` when none apply (a plain informational script like ssh-hostkey).
    """
    sev = Severity.INFO
    if output:
        scores = [float(s) for s in _VULNERS_RE.findall(output)]
        if scores:
            sev = max_severity(sev, severity_from_cvss(max(scores)))
        if _VULNERABLE_RE.search(output):
            sev = max_severity(sev, Severity.HIGH)
    mapped = _NSE_SEVERITY.get(script_id.lower())
    if mapped is not None:
        sev = max_severity(sev, mapped)
    return sev
