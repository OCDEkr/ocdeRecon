"""Tests for named value validators and the baseline safety check."""

from __future__ import annotations

import pytest

from pentui.core.validators import ValidationFailed, validate_target, validate_value


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


# --- validate_target: IP / CIDR / range / hostname entry validation ---


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.5",
        "10.0.0.0/24",
        "10.0.5.17-10.3.200.4",  # full begin-end range
        "192.168.1.10-20",  # last-octet shorthand
        "2001:db8::1",
        "scanme.example",
        "app.example.com",
        "my-server.corp.local",  # hyphen in a label
        "dc_01.corp.local",  # underscore (AD/Windows names)
        "example.com.",  # trailing root dot
    ],
)
def test_valid_targets(value):
    assert validate_target(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "10.0.0.5-1",  # reversed range — the bug that motivated this
        "10.0.0.0-oops",  # IP head, garbage tail
        "10.0.0.256",  # octet out of range
        "300.1.1.1",
        "10.0.0.0/33",  # bad prefix
        "10.0.0.1-10.0.0",  # malformed end
        "",
        "not a hostname",  # embedded space
        "*.example.com",  # wildcard not allowed
    ],
)
def test_invalid_targets_rejected(value):
    with pytest.raises(ValidationFailed):
        validate_target(value)


def test_target_shell_metacharacters_rejected():
    with pytest.raises(ValidationFailed):
        validate_target("10.0.0.1;reboot")


def test_numeric_typo_is_reported_not_treated_as_hostname():
    # The whole point: a value that was meant as an address must not silently
    # pass as a hostname just because it failed to parse as a range.
    with pytest.raises(ValidationFailed, match="IP / CIDR / range"):
        validate_target("10.0.0.5-1")


# --- check_target_list: per-token validation of a whitespace/comma list ---


def test_check_target_list_accepts_mixed_valid_tokens():
    from pentui.tui.validators import check_target_list

    assert check_target_list("10.0.0.0/24, 10.0.5.17-10.3.200.4  app.example") is None


def test_check_target_list_reports_first_bad_token():
    from pentui.tui.validators import check_target_list

    error = check_target_list("10.0.0.0/24 10.0.0.5-1")
    assert error is not None and "10.0.0.5-1" in error


def test_check_target_list_empty_allowed_unless_required():
    from pentui.tui.validators import check_target_list

    assert check_target_list("   ") is None
    assert check_target_list("", required=True) is not None
