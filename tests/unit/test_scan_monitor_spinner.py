"""The scan-monitor 'Running' heartbeat (animated spinner + elapsed clock).

Exercises the timer callbacks in isolation — no live terminal — by building the
screen without Textual's Screen.__init__ and stubbing the status widget.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from pentui.core.models import Scan
from pentui.tui.screens.scan_monitor import ScanMonitorScreen


class _FakeStatic:
    def __init__(self) -> None:
        self.text = ""

    def update(self, text: str) -> None:
        self.text = text


class _FakeTimer:
    def __init__(self) -> None:
        self.stopped = 0

    def stop(self) -> None:
        self.stopped += 1


def _screen(scan: Scan) -> tuple[ScanMonitorScreen, _FakeStatic]:
    screen = object.__new__(ScanMonitorScreen)
    screen.scan = scan
    screen._spin = None
    screen._spin_frame = 0
    status = _FakeStatic()
    screen.query_one = lambda *_args, **_kw: status  # type: ignore[method-assign]
    return screen, status


def test_tick_shows_running_with_spinner_and_elapsed():
    scan = Scan(project_id=1, tool="nmap", started_at=datetime.now() - timedelta(seconds=75))
    screen, status = _screen(scan)
    screen._tick()
    assert "Running" in status.text
    # 75s elapsed -> "1:15", and one spinner frame is present.
    assert "(1:15)" in status.text
    assert any(frame in status.text for frame in ScanMonitorScreen._SPINNER)


def test_tick_advances_frame_each_call():
    scan = Scan(project_id=1, tool="nmap", started_at=datetime.now())
    screen, _ = _screen(scan)
    screen._tick()
    screen._tick()
    assert screen._spin_frame == 2


def test_stop_spin_is_idempotent():
    scan = Scan(project_id=1, tool="nmap")
    screen, _ = _screen(scan)
    timer = _FakeTimer()
    screen._spin = timer  # type: ignore[assignment]
    screen._stop_spin()
    screen._stop_spin()  # second call must be a no-op
    assert timer.stopped == 1
    assert screen._spin is None
