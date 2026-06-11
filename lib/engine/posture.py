"""
Session noise posture + the automation dial.

Two related knobs:

  * **level** — the current manual ceiling on the noise ladder. The console opens
    at PASSIVE (zero packets sent) and the operator raises it deliberately. An
    action may run only when `tier <= level` (and, for RED, only when armed).

  * **dial** — the ``--level 0-9`` startup automation knob. It decides how far a
    launch-time ``run-all`` auto-climbs the ladder, whether RED is unlocked, and
    whether footprint warnings / red countdowns are suppressed. 0 = fully manual
    and quiet; 9 = run everything, warnings off (for efficient self-testing).

This module is pure policy — no I/O. The console composes ``allows()`` /
``red_unlocked()`` / ``suppress_warnings()`` into the actual prompts, countdowns,
and footprint banners.
"""
from __future__ import annotations

from lib.engine.action import Tier

# Dial → how far a startup run-all auto-climbs. None means "don't auto-run".
_AUTO_CEILING = {
    0: None,
    1: Tier.GREEN, 2: Tier.GREEN, 3: Tier.GREEN,
    4: Tier.YELLOW, 5: Tier.YELLOW, 6: Tier.YELLOW,
    7: Tier.RED, 8: Tier.RED, 9: Tier.RED,
}

_RED_UNLOCK_DIAL = 7    # dial >= this unlocks RED without an explicit arm
_SUPPRESS_DIAL = 9      # dial >= this suppresses footprint warnings + red countdown
_MIN_DIAL, _MAX_DIAL = 0, 9


class Posture:
    def __init__(self, dial: int = 0):
        if not (_MIN_DIAL <= dial <= _MAX_DIAL):
            raise ValueError(f"--level must be {_MIN_DIAL}..{_MAX_DIAL}, got {dial}")
        self.dial = dial
        self.level: Tier = Tier.PASSIVE       # console opens here, having sent nothing
        self._armed = dial >= _RED_UNLOCK_DIAL  # explicit dangerous unlock

    # ── policy queries ────────────────────────────────────────────────────────
    def red_unlocked(self) -> bool:
        """RED actions are only ever permitted when armed (high dial or explicit)."""
        return self._armed

    def suppress_warnings(self) -> bool:
        """Top of the dial: skip footprint banners and the red countdown."""
        return self.dial >= _SUPPRESS_DIAL

    def auto_ceiling(self) -> Tier | None:
        """Tier a launch-time run-all should auto-climb to, or None for manual."""
        return _AUTO_CEILING[self.dial]

    def allows(self, tier: Tier) -> bool:
        """May an action of this tier run under the current posture?"""
        if tier >= Tier.RED and not self._armed:
            return False
        return tier <= self.level

    # ── operator controls ─────────────────────────────────────────────────────
    def arm_dangerous(self) -> None:
        """Explicitly unlock RED (e.g. an in-session `set dangerous on`)."""
        self._armed = True

    def raise_to(self, tier: Tier) -> bool:
        """Raise the ceiling. Refuses to reach RED unless armed; returns success."""
        if tier >= Tier.RED and not self._armed:
            return False
        if tier > self.level:
            self.level = tier
        return True

    def lower_to(self, tier: Tier) -> None:
        if tier < self.level:
            self.level = tier
