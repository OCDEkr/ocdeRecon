"""Named validators for `value`-type manifest options (PROJECT.md §5, §9).

A manifest option may set ``validate: <name>``; the command builder runs the
matching validator before the value reaches argv. Validators raise
``ValidationFailed`` on bad input. As a baseline defence against argv injection,
``ensure_safe`` rejects shell metacharacters in any free-text value.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from pentui.core.scope import parse_range

# Characters never legitimate in a tool argument value here; reject defensively
# even though we always exec via argv lists (never a shell).
_SHELL_METACHARS = re.compile(r"[;&|`$<>\n\r\\\"']")

_PORTS = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")

# A single DNS label: alphanumeric, with internal hyphens/underscores; 1-63 chars.
# Underscores are allowed (AD/Windows names use them); wildcards are not.
_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$")
# Characters that only appear in numeric IP/CIDR/range notation. A value made up
# solely of these (or one whose head before a '-' is an IP) was *meant* as an
# address, so a parse failure is a real error rather than a hostname.
_NUMERIC_CHARS = frozenset("0123456789.:/-")


class ValidationFailed(ValueError):
    """Raised when a value fails its named validator."""


def ensure_safe(value: str) -> str:
    if _SHELL_METACHARS.search(value):
        raise ValidationFailed(f"value contains disallowed characters: {value!r}")
    return value


def _validate_ports(value: str) -> str:
    if not _PORTS.match(value):
        raise ValidationFailed(f"invalid port spec: {value!r}")
    for part in value.split(","):
        for bound in part.split("-"):
            if not 0 <= int(bound) <= 65535:
                raise ValidationFailed(f"port out of range (0-65535): {bound}")
    return value


def _looks_numeric_intent(text: str) -> bool:
    """True when ``text`` was clearly meant as an IP/CIDR/range, so a parse
    failure should be reported rather than silently treated as a hostname."""
    if text and all(c in _NUMERIC_CHARS for c in text):
        return True
    head = text.split("-", 1)[0].strip()
    try:
        ipaddress.ip_address(head)
    except ValueError:
        return False
    return True


def _is_valid_hostname(text: str) -> bool:
    host = text.rstrip(".")  # a trailing root dot is allowed
    if not host or len(host) > 253:
        return False
    return all(_HOSTNAME_LABEL.match(label) for label in host.split("."))


def validate_target(value: str) -> str:
    """Validate one scope/target token: an IP, CIDR, IP range, or hostname.

    Ranges may be full begin-end (``10.0.5.17-10.3.200.4``) or last-octet
    shorthand (``192.168.1.10-20``). Raises ``ValidationFailed`` for anything
    malformed — so a typo like ``10.0.0.5-1`` is rejected at entry instead of
    silently falling through to the hostname path (where it would never match).
    """
    ensure_safe(value)
    text = value.strip()
    if not text:
        raise ValidationFailed("value cannot be empty")
    if parse_range(text) is not None:
        return value  # well-formed IP / CIDR / range
    if _looks_numeric_intent(text):
        raise ValidationFailed(f"invalid IP / CIDR / range: {value!r}")
    if _is_valid_hostname(text):
        return value
    raise ValidationFailed(f"not a valid IP, CIDR, range, or hostname: {value!r}")


VALIDATORS: dict[str, Callable[[str], str]] = {
    "ports": _validate_ports,
}


def validate_value(name: str | None, value: str) -> str:
    """Apply the named validator (if any) plus the baseline safety check."""
    ensure_safe(value)
    if name is None:
        return value
    validator = VALIDATORS.get(name)
    if validator is None:
        raise ValidationFailed(f"unknown validator: {name!r}")
    return validator(value)
