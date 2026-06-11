from types import SimpleNamespace

from lib.engine.action import (
    Action,
    ActionResult,
    Footprint,
    Requirement,
    Tier,
)


def _fake_facts(known: set[str]):
    """Minimal duck-typed fact store: has(key) -> key in known."""
    return SimpleNamespace(has=lambda key: key in known)


def test_tier_is_ordered_for_posture_comparison():
    assert Tier.PASSIVE < Tier.GREEN < Tier.YELLOW < Tier.RED
    assert Tier.YELLOW <= Tier.YELLOW
    assert Tier.GREEN.label == "green"


def test_footprint_defaults_empty():
    assert Footprint().is_empty()
    assert not Footprint(summary="leaves a 4769").is_empty()
    assert not Footprint(windows_events=("4624",)).is_empty()


def test_action_defaults_to_available():
    a = Action(name="discovery.tcp_ports", tier=Tier.GREEN, handler=lambda ctx: ActionResult())
    assert a.is_available(_fake_facts(set())) is True
    assert a.missing_requirements(_fake_facts(set())) == []


def test_action_gate_controls_availability():
    a = Action(
        name="kerberos.kerberoast",
        tier=Tier.YELLOW,
        handler=lambda ctx: ActionResult(),
        gate=lambda facts: facts.has("domain") and facts.has("valid_cred"),
        requires=(
            Requirement("domain", "a domain"),
            Requirement("valid_cred", "a valid credential"),
        ),
    )
    assert a.is_available(_fake_facts(set())) is False
    assert a.is_available(_fake_facts({"domain"})) is False
    assert a.is_available(_fake_facts({"domain", "valid_cred"})) is True


def test_missing_requirements_renders_human_labels():
    a = Action(
        name="ad.bloodhound",
        tier=Tier.YELLOW,
        handler=lambda ctx: ActionResult(),
        gate=lambda facts: facts.has("domain") and facts.has("valid_cred"),
        requires=(
            Requirement("domain", "a domain"),
            Requirement("valid_cred", "a valid credential"),
        ),
    )
    missing = a.missing_requirements(_fake_facts({"domain"}))
    assert [r.label for r in missing] == ["a valid credential"]
