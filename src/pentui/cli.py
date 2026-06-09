"""Command-line entry point. Parses arguments and launches the Textual app."""

from __future__ import annotations

import argparse

from pentui import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pentui",
        description="TUI for wrapping and automating offensive-security tools.",
    )
    parser.add_argument("--version", action="version", version=f"pentui {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    # Imported lazily so `pentui --version` works without a TTY/Textual setup.
    from pentui.app import PentuiApp

    PentuiApp().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
