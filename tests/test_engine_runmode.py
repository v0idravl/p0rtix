"""CLI + end-to-end (line-mode) smoke for --mode console. No tools run: the
console reads scripted commands and the nmap/service calls are monkeypatched."""
import sys
from types import SimpleNamespace

import pytest

import p0rtix
from lib import nmap, services
from lib.engine import console as console_mod
from lib.engine.runmode import run_console_mode


def test_level_flag_parses_and_defaults_zero(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["p0rtix.py", "10.0.0.5", "--mode", "console"])
    args = p0rtix.parse_args()
    assert args.mode == "console"
    assert args.level == 0


def test_level_flag_accepts_value(monkeypatch):
    monkeypatch.setattr(sys, "argv",
                        ["p0rtix.py", "10.0.0.5", "--mode", "console", "--level", "9"])
    args = p0rtix.parse_args()
    assert args.level == 9


def _args(tmp_path, **over):
    base = dict(workspace=str(tmp_path), deep=False, users=None, level=0)
    base.update(over)
    return SimpleNamespace(**base)


def test_console_mode_runs_in_line_mode(tmp_path, monkeypatch):
    # Force the line-mode path (no textual) and feed scripted input.
    monkeypatch.setattr(console_mod, "_HAS_TEXTUAL", False)
    monkeypatch.setattr(nmap, "discover_tcp_quick", lambda ip, r, ws: [445])
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws, exclude=None: [445])
    monkeypatch.setattr(nmap, "discover_udp", lambda ip, r, ws: [])
    monkeypatch.setattr(nmap, "version_detect", lambda ip, ports, r, ws: [])

    pushed = {}

    def fake_users(ip, port, runner, buf, available):
        runner.ws.add_user("alice", authoritative=True)
        pushed["ran"] = True

    monkeypatch.setattr(services, "_smb_users", fake_users)

    script = iter(["noise green", "run discovery.tcp_ports",
                   "run smb.users", "status", "exit"])
    monkeypatch.setattr("builtins.input", lambda *a: next(script))

    run_console_mode("192.0.2.10", None, "cli-console", _args(tmp_path),
                     available={"nmap", "nxc", "ldapsearch"})

    assert pushed.get("ran") is True
    findings = (tmp_path / "cli-console" / "findings.md").read_text()
    assert "445" in findings


def test_console_mode_dial9_autoruns_without_input(tmp_path, monkeypatch):
    monkeypatch.setattr(console_mod, "_HAS_TEXTUAL", False)
    monkeypatch.setattr(nmap, "discover_tcp_quick", lambda ip, r, ws: [445])
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws, exclude=None: [445])
    monkeypatch.setattr(nmap, "discover_udp", lambda ip, r, ws: [])
    monkeypatch.setattr(nmap, "version_detect", lambda ip, ports, r, ws: [])
    for fn in ("_smb_users", "_smb_shares", "_smb_spider_shares", "_smb_policy"):
        monkeypatch.setattr(services, fn, lambda *a, **k: None)

    # dial 9 should auto-run everything up front, so an immediate EOF still works.
    monkeypatch.setattr("builtins.input", lambda *a: (_ for _ in ()).throw(EOFError))

    run_console_mode("192.0.2.10", None, "dial9", _args(tmp_path, level=9),
                     available={"nmap", "nxc", "ldapsearch"})

    findings = (tmp_path / "dial9" / "findings.md").read_text()
    assert "445" in findings
