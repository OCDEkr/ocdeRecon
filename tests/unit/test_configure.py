"""`pentui configure` — global-settings provisioning (used by deploy.sh)."""

from __future__ import annotations

from pathlib import Path

from pentui.cli import main
from pentui.config import AppConfig


def _config(tmp_path: Path, monkeypatch) -> AppConfig:  # noqa: ANN001
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    # Env overrides would mask stored values; clear them so we read settings.json.
    for var in ("NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY"):
        monkeypatch.delenv(var, raising=False)
    return AppConfig()


def test_flags_write_nessus_and_output_root(tmp_path, monkeypatch, capsys):
    config = _config(tmp_path, monkeypatch)

    rc = main(
        [
            "configure",
            "--nessus-url",
            "https://nessus.local:8834",
            "--nessus-access-key",
            "acc123",
            "--nessus-secret-key",
            "sec456",
            "--output-root",
            str(tmp_path / "pentests"),
            "--theme",
            "light",
            "--palette",
            "cb",
        ]
    )
    assert rc == 0
    assert "settings updated" in capsys.readouterr().out

    nessus = config.nessus_settings()
    assert nessus.url == "https://nessus.local:8834"
    assert nessus.access_key == "acc123"
    assert nessus.secret_key == "sec456"
    assert nessus.configured
    assert config.output_root() == tmp_path / "pentests"
    assert config.theme_mode() == "light"
    assert config.palette() == "cb"


def test_partial_flags_preserve_other_settings(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    config.set_nessus_settings(url="https://keep.me:8834", access_key="orig", secret_key="origsec")

    # Update only the secret key; url + access key must survive.
    rc = main(["configure", "--nessus-secret-key", "rotated"])
    assert rc == 0

    nessus = config.nessus_settings()
    assert nessus.url == "https://keep.me:8834"
    assert nessus.access_key == "orig"
    assert nessus.secret_key == "rotated"


def test_no_flags_non_tty_errors(tmp_path, monkeypatch, capsys):
    _config(tmp_path, monkeypatch)
    # pytest captures stdin, so isatty() is False — the wizard must refuse rather
    # than block on input().
    rc = main(["configure"])
    assert rc == 2
    assert "not a TTY" in capsys.readouterr().err


def test_interactive_wizard_applies_and_keeps_blanks(tmp_path, monkeypatch):
    import getpass

    from pentui import cli

    config = _config(tmp_path, monkeypatch)
    config.set_nessus_settings(url="https://old:8834", access_key="oldacc", secret_key="oldsec")

    # input() prompts in order: url, access key, output root, theme, palette.
    answers = iter(["https://new:8834", "", str(tmp_path / "out"), "light", "cb"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(answers))
    # getpass for the secret key — blank keeps the stored secret.
    monkeypatch.setattr(getpass, "getpass", lambda _prompt="": "")

    assert cli._interactive_configure(config) == 0

    nessus = config.nessus_settings()
    assert nessus.url == "https://new:8834"
    assert nessus.access_key == "oldacc"  # blank kept the stored value
    assert nessus.secret_key == "oldsec"  # blank getpass kept it too
    assert config.output_root() == tmp_path / "out"
    assert config.theme_mode() == "light"
    assert config.palette() == "cb"


def test_output_root_can_be_cleared(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    config.set_output_root(str(tmp_path / "pentests"))
    assert config.output_root() is not None

    rc = main(["configure", "--output-root", ""])
    assert rc == 0
    assert config.output_root() is None
