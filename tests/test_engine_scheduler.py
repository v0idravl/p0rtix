from lib.engine.action import Action, ActionResult, Tier
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.registry import ActionRegistry
from lib.engine.scheduler import Scheduler


def _store(tmp_path):
    return FactStore("192.0.2.10", None, "sched-test", str(tmp_path))


def _green(posture_level=Tier.GREEN):
    p = Posture()
    p.raise_to(posture_level)
    return p


def test_dispatch_runs_handler_and_marks_tried(tmp_path):
    fs = _store(tmp_path)
    reg = ActionRegistry()
    ran = []
    reg.register(Action("a", Tier.GREEN, lambda ctx: ran.append("a") or ActionResult()))
    sched = Scheduler(reg, fs, _green())

    sched.run_action("a")
    assert ran == ["a"]
    assert "a" in sched.tried
    # re-dispatch is a no-op
    sched.dispatch(reg.get("a"), {})
    assert ran == ["a"]


def test_run_all_cascades_on_unlocked_facts(tmp_path):
    fs = _store(tmp_path)
    reg = ActionRegistry()

    # A (always available) discovers a domain, which unlocks B.
    def handler_a(ctx):
        ctx.facts.set_discovered_domain("test.htb")
        return ActionResult()

    reg.register(Action("A", Tier.GREEN, handler_a))
    reg.register(Action("B", Tier.GREEN, lambda ctx: ActionResult(),
                        gate=lambda f: f.has("domain")))

    sched = Scheduler(reg, fs, _green())
    n = sched.run_all_at_or_below()

    names = [name for name, _ in sched.completed]
    assert names == ["A", "B"]          # B only ran because A unlocked it
    assert n == 2


def test_run_all_respects_posture_ceiling(tmp_path):
    fs = _store(tmp_path)
    reg = ActionRegistry()
    reg.register(Action("green", Tier.GREEN, lambda ctx: ActionResult()))
    reg.register(Action("yellow", Tier.YELLOW, lambda ctx: ActionResult()))

    sched = Scheduler(reg, fs, _green(Tier.GREEN))
    sched.run_all_at_or_below()
    names = {name for name, _ in sched.completed}
    assert names == {"green"}            # yellow blocked at green posture


def test_per_port_instances_each_dispatched(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_open_port("tcp", 80)
    reg = ActionRegistry()
    seen = []
    reg.register(Action(
        "vd", Tier.GREEN, lambda ctx: seen.append(ctx.target_port) or ActionResult(),
        instances=lambda f: [{"port": p} for (pr, p) in f.snapshot()["open_ports"]],
    ))
    sched = Scheduler(reg, fs, _green())
    sched.run_all_at_or_below()
    assert sorted(seen) == [22, 80]


def test_handler_exception_does_not_kill_engine(tmp_path):
    fs = _store(tmp_path)
    reg = ActionRegistry()

    def boom(ctx):
        raise RuntimeError("kaboom")

    reg.register(Action("boom", Tier.GREEN, boom))
    reg.register(Action("ok", Tier.GREEN, lambda ctx: ActionResult()))
    sched = Scheduler(reg, fs, _green())

    sched.run_all_at_or_below()         # must not raise
    assert {n for n, _ in sched.completed} == {"boom", "ok"}


def test_queue_enqueue_and_step(tmp_path):
    fs = _store(tmp_path)
    reg = ActionRegistry()
    order = []
    reg.register(Action("a", Tier.GREEN, lambda ctx: order.append("a") or ActionResult()))
    reg.register(Action("b", Tier.GREEN, lambda ctx: order.append("b") or ActionResult()))
    sched = Scheduler(reg, fs, _green())

    sched.enqueue(reg.get("a"), {})
    sched.enqueue(reg.get("b"), {})
    assert sched.enqueue(reg.get("a"), {}) is False   # dup not re-queued
    assert sched.drain() == 2
    assert order == ["a", "b"]


def test_findings_flushed_in_completion_order(tmp_path):
    fs = _store(tmp_path)
    from lib.findings import Findings
    findings = Findings(tmp_path / "findings.md", "192.0.2.10", None)
    findings.h2("Service Findings")

    reg = ActionRegistry()

    def mk(tag):
        def h(ctx):
            ctx.findings.bullet(f"ran {tag}")
            return ActionResult()
        return h

    reg.register(Action("first", Tier.GREEN, mk("first")))
    reg.register(Action("second", Tier.GREEN, mk("second")))
    sched = Scheduler(reg, fs, _green(), findings=findings)

    sched.run_action("first")
    sched.run_action("second")
    findings.finalize()

    body = (tmp_path / "findings.md").read_text()
    assert body.index("ran first") < body.index("ran second")


def test_tried_set_persists_across_sessions(tmp_path):
    fs = _store(tmp_path)
    reg = ActionRegistry()
    reg.register(Action("once", Tier.GREEN, lambda ctx: ActionResult()))
    sched = Scheduler(reg, fs, _green())
    sched.run_action("once")
    assert "once" in sched.tried

    # New scheduler over the same workspace restores the tried set.
    fs2 = _store(tmp_path)
    reg2 = ActionRegistry()
    ran = []
    reg2.register(Action("once", Tier.GREEN, lambda ctx: ran.append(1) or ActionResult()))
    sched2 = Scheduler(reg2, fs2, _green())
    assert "once" in sched2.tried
    assert sched2.run_all_at_or_below() == 0    # nothing re-runs
    assert ran == []


def test_recheck_users_clears_collect_once(tmp_path):
    fs = _store(tmp_path)
    fs.mark_users_complete()
    reg = ActionRegistry()
    sched = Scheduler(reg, fs, _green())
    assert fs.users_complete is True
    sched.recheck_users()
    assert fs.users_complete is False


def test_recheck_rearms_a_dormant_branch(tmp_path):
    from lib.engine.facts import ProtoStatus
    fs = _store(tmp_path)
    reg = ActionRegistry()
    reg.register(Action("ldap.anon_bind", Tier.GREEN, lambda ctx: ActionResult(),
                        group="ldap", suppressed_by=(ProtoStatus.ANON_DENIED,)))
    sched = Scheduler(reg, fs, _green())

    sched.run_action("ldap.anon_bind")
    fs.set_proto_status("ldap", ProtoStatus.ANON_DENIED)
    assert "ldap.anon_bind" in sched.tried
    assert "ldap.anon_bind" not in {a.name for a, _ in reg.available(fs, sched._posture)}

    n = sched.recheck("ldap")
    assert n == 1
    assert fs.proto_status("ldap") is None              # status cleared
    assert "ldap.anon_bind" not in sched.tried          # tried-state dropped
    assert "ldap.anon_bind" in {a.name for a, _ in reg.available(fs, sched._posture)}
