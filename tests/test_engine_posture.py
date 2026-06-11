import pytest

from lib.engine.action import Tier
from lib.engine.posture import Posture


def test_opens_passive_and_manual_by_default():
    p = Posture()
    assert p.level is Tier.PASSIVE
    assert p.dial == 0
    assert p.auto_ceiling() is None
    assert p.red_unlocked() is False
    assert p.suppress_warnings() is False


def test_dial_must_be_in_range():
    with pytest.raises(ValueError):
        Posture(dial=10)
    with pytest.raises(ValueError):
        Posture(dial=-1)


def test_allows_matrix_respects_level_and_arming():
    p = Posture()
    # At PASSIVE, only passive runs.
    assert p.allows(Tier.PASSIVE) is True
    assert p.allows(Tier.GREEN) is False

    assert p.raise_to(Tier.GREEN) is True
    assert p.allows(Tier.GREEN) is True
    assert p.allows(Tier.YELLOW) is False

    assert p.raise_to(Tier.YELLOW) is True
    assert p.allows(Tier.YELLOW) is True
    # RED never allowed while unarmed, even if we ask to raise to it.
    assert p.raise_to(Tier.RED) is False
    assert p.allows(Tier.RED) is False
    assert p.level is Tier.YELLOW   # raise refused, ceiling unchanged


def test_arming_unlocks_red():
    p = Posture()
    p.arm_dangerous()
    assert p.red_unlocked() is True
    assert p.raise_to(Tier.RED) is True
    assert p.allows(Tier.RED) is True


def test_lower_to_drops_ceiling():
    p = Posture()
    p.raise_to(Tier.YELLOW)
    p.lower_to(Tier.GREEN)
    assert p.level is Tier.GREEN
    assert p.allows(Tier.YELLOW) is False


def test_dial_auto_ceiling_mapping():
    assert Posture(dial=2).auto_ceiling() is Tier.GREEN
    assert Posture(dial=5).auto_ceiling() is Tier.YELLOW
    assert Posture(dial=8).auto_ceiling() is Tier.RED


def test_high_dial_arms_red_and_suppresses_warnings():
    p7 = Posture(dial=7)
    assert p7.red_unlocked() is True
    assert p7.suppress_warnings() is False     # 7 still shows the countdown

    p9 = Posture(dial=9)
    assert p9.red_unlocked() is True
    assert p9.suppress_warnings() is True
    assert p9.raise_to(Tier.RED) is True
