from lib.engine.action import Action, ActionResult, Requirement, Tier
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.registry import ActionRegistry, instance_key


def _noop(ctx):
    return ActionResult()


def _store(tmp_path):
    return FactStore("192.0.2.10", None, "reg-test", str(tmp_path))


def _green_posture():
    p = Posture()
    p.raise_to(Tier.GREEN)
    return p


def _tcp_ports(facts):
    return [{"port": p} for (proto, p) in facts.snapshot()["open_ports"] if proto == "tcp"]


def _registry():
    reg = ActionRegistry()
    reg.register(Action("discovery.tcp_ports", Tier.GREEN, _noop))
    reg.register(Action(
        "svc.version_detect", Tier.GREEN, _noop, instances=_tcp_ports,
    ))
    reg.register(Action(
        "kerberos.kerberoast", Tier.YELLOW, _noop,
        gate=lambda f: f.has("domain") and f.has("valid_cred"),
        requires=(Requirement("domain", "a domain"),
                  Requirement("valid_cred", "a valid credential")),
    ))
    return reg


def test_available_filters_by_gate_and_posture(tmp_path):
    reg = _registry()
    fs = _store(tmp_path)
    posture = _green_posture()

    names = {a.name for a, _ in reg.available(fs, posture)}
    # green discovery is available; yellow kerberoast gated out (no facts + posture green)
    assert "discovery.tcp_ports" in names
    assert "kerberos.kerberoast" not in names


def test_available_expands_per_port_instances(tmp_path):
    reg = _registry()
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_open_port("tcp", 445)
    posture = _green_posture()

    vd = [(a, args) for a, args in reg.available(fs, posture)
          if a.name == "svc.version_detect"]
    ports = sorted(args["port"] for _, args in vd)
    assert ports == [22, 445]


def test_tried_instances_are_excluded(tmp_path):
    reg = _registry()
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_open_port("tcp", 445)
    posture = _green_posture()

    tried = {instance_key("svc.version_detect", {"port": 22})}
    vd = [args for a, args in reg.available(fs, posture, tried=tried)
          if a.name == "svc.version_detect"]
    assert [a["port"] for a in vd] == [445]


def test_deps_filter(tmp_path):
    reg = ActionRegistry()
    reg.register(Action("needs.tool", Tier.GREEN, _noop, deps=("certipy-ad",)))
    fs = _store(tmp_path)
    posture = _green_posture()

    assert reg.available(fs, posture, tools=set()) == []
    got = reg.available(fs, posture, tools={"certipy-ad"})
    assert [a.name for a, _ in got] == ["needs.tool"]


def test_dormant_lists_missing_requirements(tmp_path):
    reg = _registry()
    fs = _store(tmp_path)
    fs.set_discovered_domain("test.htb")     # satisfies one requirement only

    dormant = dict((a.name, reqs) for a, reqs in reg.dormant(fs))
    assert "kerberos.kerberoast" in dormant
    assert [r.label for r in dormant["kerberos.kerberoast"]] == ["a valid credential"]


def test_unlock_on_new_fact_moves_dormant_to_available(tmp_path):
    reg = _registry()
    fs = _store(tmp_path)
    posture = Posture()
    posture.raise_to(Tier.YELLOW)

    assert "kerberos.kerberoast" not in {a.name for a, _ in reg.available(fs, posture)}
    fs.set_discovered_domain("test.htb")
    fs.add_valid_cred("bob", "Pass1", "smb")
    assert "kerberos.kerberoast" in {a.name for a, _ in reg.available(fs, posture)}


def test_exhausted_after_all_instances_run(tmp_path):
    reg = _registry()
    fs = _store(tmp_path)
    tried = {"discovery.tcp_ports"}
    exhausted = {a.name for a in reg.exhausted(fs, tried)}
    assert "discovery.tcp_ports" in exhausted
    assert "svc.version_detect" not in exhausted


def test_why_explains_each_state(tmp_path):
    reg = _registry()
    fs = _store(tmp_path)
    green = _green_posture()

    # dormant — missing facts
    assert "needs:" in reg.why("kerberos.kerberoast", fs, green)
    # blocked by posture (gate ok but tier above level)
    fs.set_discovered_domain("test.htb")
    fs.add_valid_cred("bob", "Pass1", "smb")
    assert "noise level" in reg.why("kerberos.kerberoast", fs, green)
    # available
    assert reg.why("discovery.tcp_ports", fs, green) == "available"
    # exhausted
    assert "exhausted" in reg.why("discovery.tcp_ports", fs, green,
                                  tried={"discovery.tcp_ports"})
    # unknown
    assert "no such action" in reg.why("nope", fs, green)


def test_supersedes_skips_covered_action(tmp_path):
    reg = ActionRegistry()
    reg.register(Action("smb.anon_enum", Tier.GREEN, _noop,
                        supersedes=("enum4linux",)))
    reg.register(Action("enum4linux", Tier.GREEN, _noop))
    fs = _store(tmp_path)
    posture = _green_posture()

    tried = {"smb.anon_enum"}
    names = {a.name for a, _ in reg.available(fs, posture, tried=tried)}
    assert "enum4linux" not in names
    assert "covered by a superseding action" in reg.why("enum4linux", fs, posture, tried=tried)
