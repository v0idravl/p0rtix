"""Tests for the line-mode console driver and the dial autorun. The Textual
dashboard itself is exercised on a box with textual installed; here we drive the
dependency-free seam."""
from lib import nmap, services
from lib.engine.action import Tier
from lib.engine.actions_builtin import build_registry
from lib.engine.commands import CommandRouter
from lib.engine.console import LineConsole, apply_dial_autorun
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler


class _FakeRunner:
    def __init__(self, ws):
        self.ws = ws


def _wire(tmp_path, dial=0):
    fs = FactStore("192.0.2.10", None, "console-test", str(tmp_path))
    posture = Posture(dial=dial)
    reg = build_registry()
    sched = Scheduler(reg, fs, posture, ip="192.0.2.10", runner=_FakeRunner(fs),
                      tools={"nmap", "nxc", "ldapsearch"})
    return fs, posture, reg, sched


def _scripted_reader(lines):
    it = iter(lines)

    def reader(_prompt):
        try:
            return next(it)
        except StopIteration:
            raise EOFError

    return reader


def test_line_console_runs_commands_until_exit(tmp_path):
    fs, posture, reg, sched = _wire(tmp_path)
    router = CommandRouter(sched, reg, fs, posture)
    out = []
    LineConsole(router).run(reader=_scripted_reader(["noise green", "status", "exit"]),
                            writer=out.append)
    joined = "\n".join(out)
    assert "raised to green" in joined
    assert "posture  green" in joined


def test_line_console_stops_on_eof(tmp_path):
    fs, posture, reg, sched = _wire(tmp_path)
    router = CommandRouter(sched, reg, fs, posture)
    out = []
    # No 'exit' — reader raises EOFError when exhausted; must terminate.
    LineConsole(router).run(reader=_scripted_reader(["help"]), writer=out.append)
    assert any("commands:" in o for o in out)


def test_dial_zero_is_fully_manual(tmp_path):
    fs, posture, reg, sched = _wire(tmp_path, dial=0)
    assert apply_dial_autorun(sched, posture) == 0
    assert posture.level is Tier.PASSIVE
    assert sched.completed == []


def test_dial_drives_green_autorun(tmp_path, monkeypatch):
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws, exclude=None: [445])
    monkeypatch.setattr(nmap, "discover_udp", lambda ip, r, ws: [])
    monkeypatch.setattr(nmap, "version_detect", lambda ip, ports, r, ws: [])
    for fn in ("_smb_users", "_smb_shares", "_smb_spider_shares", "_smb_policy"):
        monkeypatch.setattr(services, fn, lambda *a, **k: None)

    fs, posture, reg, sched = _wire(tmp_path, dial=2)   # dial 2 → auto green
    apply_dial_autorun(sched, posture)

    assert posture.level is Tier.GREEN
    names = {n for n, _ in sched.completed}
    assert "discovery.tcp_ports" in names      # auto-ran the green sweep
    assert "smb.users" in names                # and cascaded into 445 enum
