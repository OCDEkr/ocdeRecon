"""Tests for named value validators and the baseline safety check."""

from __future__ import annotations

import pytest

from pentui.core.validators import ValidationFailed, validate_value


@pytest.mark.parametrize("value", ["80", "1-65535", "22,80,443", "1-1000,3389,8080-8090"])
def test_valid_ports(value):
    assert validate_value("ports", value) == value


@pytest.mark.parametrize("value", ["", "abc", "80,", "70000", "1-70000", "80 443"])
def test_invalid_ports(value):
    with pytest.raises(ValidationFailed):
        validate_value("ports", value)


@pytest.mark.parametrize("value", ["a; rm -rf /", "x && y", "`id`", "$(id)", "a|b", "x>y"])
def test_shell_metacharacters_rejected(value):
    with pytest.raises(ValidationFailed):
        validate_value(None, value)


def test_unknown_validator_rejected():
    with pytest.raises(ValidationFailed):
        validate_value("nope", "x")


def test_no_validator_passes_safe_value():
    assert validate_value(None, "10.0.0.0/24") == "10.0.0.0/24"
