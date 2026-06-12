"""Headless tests for the Textual operator dashboard, driven through Textual's
Pilot harness (no TTY needed). These guard the wiring the line-mode tests can't
reach: action-list rendering, fact-driven refresh, click/enter-to-run, the
command box, and the worker/thread marshalling that a live scan relies on."""
import asyncio

import pytest

textual = pytest.importorskip("textual")

from lib.engine.action import Tier
from lib.engine.actions_builtin import build_registry
from lib.engine.commands import CommandRouter
from lib.engine.console import _build_dashboard
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler


class _FakeRunner:
    def __init__(self, ws):
        self.ws = ws


def _wire(tmp_path, level=Tier.GREEN):
    fs = FactStore("10.0.0.9", None, "ui-test", str(tmp_path))
    posture = Posture()
    posture.raise_to(level)
    reg = build_registry()
    sched = Scheduler(reg, fs, posture, ip="10.0.0.9", runner=_FakeRunner(fs),
                      tools={"nmap", "nxc", "ldapsearch", "impacket-GetNPUsers",
                             "hashcat"})
    router = CommandRouter(sched, reg, fs, posture)
    return fs, posture, reg, sched, router


def _rows(app):
    from textual.widgets import ListView
    lv = app.query_one("#actions", ListView)
    # _ActionItem lives in a closure; identify rows by their marker attribute.
    return [c for c in lv.children if hasattr(c, "action_name")]


def _runnable_names(app):
    return [c.action_name for c in _rows(app) if c.runnable]


def _state_text(app):
    from textual.widgets import Static
    return str(app.query_one("#state", Static).render())


def _run(coro):
    asyncio.run(coro)


def test_dashboard_mounts_and_lists_actions(tmp_path):
    fs, posture, reg, sched, router = _wire(tmp_path)
    app = _build_dashboard(router, sched, reg, fs, posture)

    async def body():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            rows = _rows(app)
            assert rows, "action list should not be empty"
            # discovery is available with nothing learned yet
            assert "discovery.tcp_ports" in _runnable_names(app)
            # smb is dormant until 445 is known
            state = _state_text(app)
            assert "TARGET" in state and "10.0.0.9" in state

    _run(body())


def test_new_fact_unlocks_action_in_list(tmp_path):
    fs, posture, reg, sched, router = _wire(tmp_path)
    app = _build_dashboard(router, sched, reg, fs, posture)

    async def body():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            assert "smb.anon_enum" not in _runnable_names(app)
            fs.add_open_port("tcp", 445)          # emit fact on the UI thread
            await pilot.pause()
            assert "smb.anon_enum" in _runnable_names(app)

    _run(body())


def test_command_box_sets_domain_without_crashing(tmp_path):
    fs, posture, reg, sched, router = _wire(tmp_path)
    app = _build_dashboard(router, sched, reg, fs, posture)

    async def body():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            inp = app.query_one("#cmd")
            inp.focus()
            inp.value = "set domain htb.local"
            await pilot.press("enter")
            await pilot.pause()
            assert "htb.local" in _state_text(app)

    _run(body())


def test_input_sits_above_footer_no_overlap(tmp_path):
    # Regression: the command input used to dock:bottom and overlap the Footer.
    fs, posture, reg, sched, router = _wire(tmp_path)
    app = _build_dashboard(router, sched, reg, fs, posture)

    async def body():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            cmd = app.query_one("#cmd").region
            foot = app.query_one("Footer").region
            log = app.query_one("#log").region
            assert cmd.height >= 3
            assert cmd.y + cmd.height <= foot.y       # input above footer
            assert log.y + log.height <= cmd.y        # log above input
            assert log.height > 0

    _run(body())


def test_selecting_runnable_action_dispatches(tmp_path, monkeypatch):
    from lib import nmap
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws, exclude=None: [445])
    fs, posture, reg, sched, router = _wire(tmp_path)
    app = _build_dashboard(router, sched, reg, fs, posture)

    async def body():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            # run discovery via the command box (worker thread path)
            inp = app.query_one("#cmd")
            inp.focus()
            inp.value = "run discovery.tcp_ports"
            await pilot.press("enter")
            # wait for the worker to finish
            await app.workers.wait_for_complete()
            await pilot.pause()
            assert fs.has("tcp/445")

    _run(body())


def test_actions_rendered_grouped_by_path(tmp_path):
    fs, posture, reg, sched, router = _wire(tmp_path)
    app = _build_dashboard(router, sched, reg, fs, posture)

    async def body():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            fs.add_open_port("tcp", 445)
            await pilot.pause()
            from textual.widgets import ListView
            lv = app.query_one("#actions", ListView)
            labels = [getattr(c, "label_text", "") for c in lv.children]
            # group headers present, in path order
            assert any("DISCOVERY" in l for l in labels)
            assert any("▸ SMB" in l for l in labels)
            # the SMB header sits above the smb.anon_enum row
            smb_hdr = next(i for i, l in enumerate(labels) if "▸ SMB" in l)
            smb_row = next(i for i, l in enumerate(labels) if "smb.anon_enum" in l)
            assert smb_hdr < smb_row

    _run(body())


def test_state_pane_is_status_summary(tmp_path):
    fs, posture, reg, sched, router = _wire(tmp_path)
    fs.add_open_port("tcp", 445)
    fs.set_discovered_domain("htb.local")
    app = _build_dashboard(router, sched, reg, fs, posture)

    async def body():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            txt = _state_text(app)
            for label in ("TARGET", "DOMAIN", "PORTS", "LOOT", "ACTIONS"):
                assert label in txt
            assert "htb.local" in txt
            assert "known" in txt          # ports shown as a count, not a dump

    _run(body())


def test_action_list_hides_fact_dormant_actions(tmp_path):
    # The list stays actionable: fact-dormant actions are not shown (only
    # available + ready-but-blocked-by-noise/tool).
    fs, posture, reg, sched, router = _wire(tmp_path)
    app = _build_dashboard(router, sched, reg, fs, posture)

    async def body():
        async with app.run_test(size=(120, 40)) as pilot:
            await pilot.pause()
            labels = [getattr(c, "label_text", "") for c in
                      app.query_one("#actions", _ListView()).children]
            text = "\n".join(labels)
            # smb.anon_enum is fact-dormant (no 445) → not in the list
            assert "smb.anon_enum" not in text
            # discovery is available → present
            assert any("discovery.tcp_quick" in l for l in labels)

    _run(body())


def _ListView():
    from textual.widgets import ListView
    return ListView
