"""The workflow-monitor running-step heartbeat.

A long, quiet step (nmap before it prints anything) must still read as alive.
Exercised in isolation — no live terminal — by building the screen without
Textual's Screen.__init__ and stubbing the steps table.
"""

from __future__ import annotations

from pentui.core.workflow import WorkflowEvent
from pentui.tui.screens.workflow_monitor import WorkflowMonitorScreen


class _FakeTable:
    def __init__(self) -> None:
        self.cells: dict[str, str] = {}

    def update_cell(self, row_key: str, _col: str, value: str) -> None:
        self.cells[row_key] = value


def _screen() -> tuple[WorkflowMonitorScreen, _FakeTable]:
    screen = object.__new__(WorkflowMonitorScreen)
    screen._running_step = None
    screen._running_since = None
    screen._spin_frame = 0
    table = _FakeTable()
    screen.query_one = lambda *_args, **_kw: table  # type: ignore[method-assign]
    return screen, table


def test_running_event_starts_the_heartbeat():
    screen, table = _screen()
    screen._on_event(WorkflowEvent(step_id="discover", kind="status", detail="running"))
    assert screen._running_step == "discover"
    screen._tick()
    cell = table.cells["discover"]
    assert cell.startswith("running ")
    assert any(frame in cell for frame in WorkflowMonitorScreen._SPINNER)


def test_terminal_event_stops_the_heartbeat():
    screen, table = _screen()
    screen._on_event(WorkflowEvent(step_id="discover", kind="status", detail="running"))
    screen._on_event(WorkflowEvent(step_id="discover", kind="status", detail="done"))
    assert screen._running_step is None
    # The cell shows the final state, and a stray tick must not overwrite it.
    assert table.cells["discover"] == "done"
    screen._tick()
    assert table.cells["discover"] == "done"


def test_tick_is_a_no_op_when_nothing_runs():
    screen, table = _screen()
    screen._tick()
    assert table.cells == {}
