"""Tests for the cross-protocol reuse spray delta.

Two things are covered here:

  (a) The relaxed gates on ``creds.spray`` / ``creds.test``: they now fire on ANY
      open auth surface (``_auth_surface``: 445/5985/5986/22/3389/1433) rather than
      only SMB/445 — so an SSH-only box gets sprayed too.

  (b) The generic ``rearm_on`` mechanism: when a fact of a declared kind newly
      lands, the scheduler's ``_on_fact`` subscriber clears that action's
      tried-state, re-arming it for the next bulk sweep. It must never dispatch
      from inside the fact handler (re-entrancy rule).

Wiring follows test_engine_access.py: a real FactStore + build_registry() +
Posture + Scheduler, with a fake runner so no spray/test ever hits the network.
"""
from lib.engine.actions_builtin import _auth_surface, build_registry
from lib.engine.action import Tier
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler


class _FakeRunner:
    """Records every .run(cmd, label, timeout=) call; returns "" (no network)."""

    def __init__(self, ws):
        self.ws = ws
        self.fresh = False
        self.calls = []

    def run(self, cmd, label, timeout=None):
        self.calls.append((cmd, label))
        return ""


def _store(tmp_path):
    return FactStore("192.0.2.10", None, "rearm-test", str(tmp_path))


def _wire(tmp_path):
    """Real registry/posture(YELLOW)/scheduler with a fake runner and nxc present."""
    fs = _store(tmp_path)
    posture = Posture()
    posture.raise_to(Tier.YELLOW)
    reg = build_registry()
    runner = _FakeRunner(fs)
    sched = Scheduler(reg, fs, posture, ip="192.0.2.10",
                      runner=runner, tools={"nxc", "nmap"})
    return fs, posture, reg, sched, runner


def _available_names(reg, fs, sched, posture):
    return {a.name for a, _ in reg.available(fs, posture, sched.tried, {"nxc", "nmap"})}


# ── 1. registry.actions_rearmed_by maps fact kinds → action names ─────────────
def test_actions_rearmed_by_maps_kinds_to_actions(tmp_path):
    reg = build_registry()
    assert reg.actions_rearmed_by("cred") == {"creds.spray"}
    assert reg.actions_rearmed_by("cred_pair") == {"creds.test"}
    assert reg.actions_rearmed_by("valid_cred") == {"creds.test"}
    assert reg.actions_rearmed_by("nonexistent") == set()


# ── 2. relaxed gates: an SSH-only box (tcp/22) is enough ──────────────────────
def test_spray_available_on_ssh_only_surface(tmp_path):
    fs, posture, reg, sched, _ = _wire(tmp_path)
    fs.add_open_port("tcp", 22)        # SSH only — previously needed tcp/445
    fs.add_cred("hunter2")             # a candidate password
    assert "creds.spray" in _available_names(reg, fs, sched, posture)


def test_test_available_on_ssh_only_surface(tmp_path):
    fs, posture, reg, sched, _ = _wire(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_cred_pair("ike", "pw")      # an unverified (user, pass) pair
    assert "creds.test" in _available_names(reg, fs, sched, posture)


# ── 3. _auth_surface: any login port satisfies it; none → False ───────────────
def test_auth_surface_true_for_each_login_port(tmp_path):
    for port in (445, 5985, 5986, 22, 3389, 1433):
        fs = _store(tmp_path)
        fs.add_open_port("tcp", port)
        assert _auth_surface(fs) is True, f"port {port} should satisfy _auth_surface"


def test_auth_surface_false_with_no_login_port(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 8080)      # not an auth surface
    fs.add_open_port("tcp", 80)
    assert _auth_surface(fs) is False


# ── 4. rearm reaction: a new matching fact clears tried-state; others don't ───
def test_new_cred_fact_rearms_spray(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_cred("first")
    # Run the spray once so it is tried/exhausted.
    sched.run_action("creds.spray")
    assert "creds.spray" in sched.tried
    assert "creds.spray" not in _available_names(reg, fs, sched, posture)

    runner.calls.clear()
    # A fresh `cred` fact re-arms the spray (subscription is live in the ctor).
    fs.add_cred("newsecret")
    assert "creds.spray" not in sched.tried          # tried-state cleared
    assert "creds.spray" in _available_names(reg, fs, sched, posture)


def test_non_matching_fact_does_not_rearm_spray(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_cred("first")
    sched.run_action("creds.spray")
    assert "creds.spray" in sched.tried

    # A port_open fact is not in creds.spray's rearm_on → tried-state stays.
    fs.add_open_port("tcp", 8080)
    assert "creds.spray" in sched.tried


# ── 5. re-entrancy safety: the listener clears state, never dispatches ────────
def test_rearm_listener_does_not_dispatch(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_cred("first")
    sched.run_action("creds.spray")
    runner.calls.clear()

    # Emitting a matching fact must return normally and run NOTHING (the listener
    # only clears tried-state; it never re-enters dispatch).
    fs.add_cred("x")
    assert runner.calls == []
    assert "creds.spray" not in sched.tried          # but it *was* re-armed
