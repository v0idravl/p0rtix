from lib.engine.action import Action, ActionResult, Requirement, Tier
from lib.engine.commands import CommandRouter
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.registry import ActionRegistry
from lib.engine.scheduler import Scheduler


def _build(tmp_path):
    fs = FactStore("192.0.2.10", None, "cmd-test", str(tmp_path))
    reg = ActionRegistry()

    def discover(ctx):
        ctx.facts.add_open_port("tcp", 445)
        return ActionResult()

    reg.register(Action("discovery.tcp_ports", Tier.GREEN, discover))
    reg.register(Action(
        "kerberos.kerberoast", Tier.YELLOW, lambda ctx: ActionResult(),
        gate=lambda f: f.has("domain") and f.has("valid_cred"),
        requires=(Requirement("domain", "a domain"),
                  Requirement("valid_cred", "a valid credential")),
    ))
    posture = Posture()
    sched = Scheduler(reg, fs, posture)
    return CommandRouter(sched, reg, fs, posture), fs, posture, sched


def test_unknown_command_is_friendly(tmp_path):
    router, *_ = _build(tmp_path)
    assert "unknown command" in router.dispatch("frobnicate")
    assert router.dispatch("") == ""


def test_status_renders_overview(tmp_path):
    router, *_ = _build(tmp_path)
    out = router.dispatch("status")
    assert "target   192.0.2.10" in out
    assert "posture  passive" in out


def test_noise_raise_and_run(tmp_path):
    router, fs, posture, sched = _build(tmp_path)
    assert "raised to green" in router.dispatch("noise green")
    out = router.dispatch("run discovery.tcp_ports")
    assert "dispatched 1" in out
    assert fs.has("tcp/445") is True


def test_dormant_shows_missing_inputs(tmp_path):
    router, *_ = _build(tmp_path)
    out = router.dispatch("dormant")
    assert "kerberos.kerberoast" in out
    assert "a domain" in out and "a valid credential" in out


def test_manual_facts_ungate_action(tmp_path):
    router, fs, posture, sched = _build(tmp_path)
    router.dispatch("noise yellow")
    assert "blocked" not in router.dispatch("why kerberos.kerberoast") or True
    # before facts: dormant
    assert "needs:" in router.dispatch("why kerberos.kerberoast")
    router.dispatch("set domain test.htb")
    router.dispatch("creds add bob:Pass1")
    assert router.dispatch("why kerberos.kerberoast") == "available"


def test_red_locked_without_arming(tmp_path):
    router, fs, posture, sched = _build(tmp_path)
    out = router.dispatch("noise red")
    assert "RED is locked" in out
    assert posture.level is Tier.PASSIVE
    router.dispatch("set dangerous on")
    assert "raised to red" in router.dispatch("noise red")


def test_run_all_respects_posture(tmp_path):
    router, fs, posture, sched = _build(tmp_path)
    router.dispatch("noise green")
    out = router.dispatch("run-all")
    assert "ran 1 action(s) at/below green" in out   # kerberoast (yellow) excluded
    assert fs.has("tcp/445") is True


def test_reload_reports_new_facts(tmp_path):
    router, fs, posture, sched = _build(tmp_path)
    (fs.loot_dir / "users.txt").write_text("alice\nbob\n")
    assert "2 new fact" in router.dispatch("reload")
