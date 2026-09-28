"""Textual input validators for IP/CIDR/range/hostname fields (PROJECT.md §11).

Scope rules (include/exclude) and target lists are whitespace/comma-separated
lists of IPs, CIDRs, IP ranges, or hostnames. These wrap the UI-free
``core.validators.validate_target`` so a malformed token (e.g. ``10.0.0.5-1``)
is caught at entry — with live red-border feedback and a blocking check in the
submit handler — instead of being stored and silently mishandled downstream.
"""

from __future__ import annotations

import re

from textual.validation import ValidationResult, Validator

from pentui.core.validators import ValidationFailed, validate_target

_SPLIT = re.compile(r"[\s,]+")


def check_target_list(raw: str, *, required: bool = False) -> str | None:
    """Return an error message for the first malformed token in a whitespace/
    comma-separated list, or ``None`` when every token is a valid
    IP/CIDR/range/hostname (an empty list is allowed unless ``required``)."""
    tokens = [t for t in _SPLIT.split(raw.strip()) if t]
    if not tokens:
        return "at least one target is required" if required else None
    for token in tokens:
        try:
            validate_target(token)
        except ValidationFailed as exc:
            return str(exc)
    return None


class TargetListValidator(Validator):
    """Live validation for an Input holding a list of IP/CIDR/range/hostname tokens."""

    def __init__(self, *, required: bool = False) -> None:
        super().__init__()
        self.required = required

    def validate(self, value: str) -> ValidationResult:
        error = check_target_list(value, required=self.required)
        return self.success() if error is None else self.failure(error)
