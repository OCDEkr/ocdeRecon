"""Named validators for `value`-type manifest options (PROJECT.md §5, §9).

A manifest option may set ``validate: <name>``; the command builder runs the
matching validator before the value reaches argv. Validators raise
``ValidationFailed`` on bad input. As a baseline defence against argv injection,
``ensure_safe`` rejects shell metacharacters in any free-text value.
"""

from __future__ import annotations

import re
from collections.abc import Callable

# Characters never legitimate in a tool argument value here; reject defensively
# even though we always exec via argv lists (never a shell).
_SHELL_METACHARS = re.compile(r"[;&|`$<>\n\r\\\"']")

_PORTS = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


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
