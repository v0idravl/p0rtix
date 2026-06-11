"""
The action registry — the single place every capability is declared.

`ActionRegistry` holds all `Action`s and answers the questions the console and
scheduler ask:

  * `available`  — runnable right now (gate satisfied, posture permits, deps
                   present, not already tried), expanded into per-instance jobs
  * `dormant`    — greyed out, waiting on a fact, with the missing inputs to show
  * `exhausted`  — already run to completion
  * `why`        — a one-line human explanation of an action's current state

Adding a new tool to p0rtix is one `register()` call (in actions_builtin.py).
"""
from __future__ import annotations

from lib.engine.action import Action, Requirement
from lib.engine.facts import FactStore
from lib.engine.posture import Posture


def instance_key(name: str, args: dict) -> str:
    """Stable identity for one dispatched instance. Per-port actions get a
    `name#port` key; single-instance actions are just `name`."""
    port = args.get("port") if args else None
    return f"{name}#{port}" if port is not None else name


class ActionRegistry:
    def __init__(self):
        self._actions: dict[str, Action] = {}

    def register(self, action: Action) -> None:
        if action.name in self._actions:
            raise ValueError(f"duplicate action name: {action.name}")
        self._actions[action.name] = action

    def get(self, name: str) -> Action | None:
        return self._actions.get(name)

    def all(self) -> list[Action]:
        return list(self._actions.values())

    # ── instance expansion ────────────────────────────────────────────────────
    def _expand(self, action: Action, facts: FactStore) -> list[dict]:
        if action.instances is None:
            return [{}]
        return action.instances(facts) or []

    def _has_run(self, action: Action, tried: set[str]) -> bool:
        prefix = action.name + "#"
        return action.name in tried or any(k.startswith(prefix) for k in tried)

    def _is_superseded(self, action: Action, tried: set[str]) -> bool:
        """True if some action that supersedes this one has already run."""
        for other in self._actions.values():
            if action.name in other.supersedes and self._has_run(other, tried):
                return True
        return False

    # ── queries ───────────────────────────────────────────────────────────────
    def available(
        self,
        facts: FactStore,
        posture: Posture,
        tried: set[str] | None = None,
        tools: set[str] | None = None,
    ) -> list[tuple[Action, dict]]:
        """Every (action, args) instance runnable under the current state."""
        tried = tried or set()
        out: list[tuple[Action, dict]] = []
        for action in self._actions.values():
            if not posture.allows(action.tier):
                continue
            if not action.is_available(facts):
                continue
            if tools is not None and action.deps and not set(action.deps) <= tools:
                continue
            if self._is_superseded(action, tried):
                continue
            for args in self._expand(action, facts):
                if instance_key(action.name, args) not in tried:
                    out.append((action, args))
        return out

    def dormant(self, facts: FactStore) -> list[tuple[Action, list[Requirement]]]:
        """Actions whose gate is unmet — greyed out, with the missing inputs.
        Independent of posture (posture-blocked is a separate, runnable-soon state
        surfaced by `why`)."""
        out = []
        for action in self._actions.values():
            if not action.is_available(facts):
                out.append((action, action.missing_requirements(facts)))
        return out

    def exhausted(self, facts: FactStore, tried: set[str]) -> list[Action]:
        """Actions that have run and have no remaining untried instance."""
        out = []
        for action in self._actions.values():
            if not self._has_run(action, tried):
                continue
            keys = [instance_key(action.name, a) for a in self._expand(action, facts)]
            if all(k in tried for k in keys):
                out.append(action)
        return out

    def why(
        self,
        name: str,
        facts: FactStore,
        posture: Posture,
        tried: set[str] | None = None,
        tools: set[str] | None = None,
    ) -> str:
        """One-line explanation of an action's current state, in plain language."""
        tried = tried or set()
        action = self._actions.get(name)
        if action is None:
            return f"no such action: {name}"

        if not action.is_available(facts):
            missing = action.missing_requirements(facts)
            if missing:
                return "dormant — needs: " + ", ".join(r.label for r in missing)
            return "dormant — preconditions not met"

        if not posture.allows(action.tier):
            if action.tier.label == "red" and not posture.red_unlocked():
                return "blocked — RED is locked (raise --level or arm dangerous)"
            return f"blocked — raise noise level to {action.tier.label}"

        if tools is not None and action.deps and not set(action.deps) <= tools:
            missing = sorted(set(action.deps) - tools)
            return "blocked — missing tool(s): " + ", ".join(missing)

        if self._is_superseded(action, tried):
            return "skipped — covered by a superseding action"

        keys = [instance_key(action.name, a) for a in self._expand(action, facts)]
        if keys and all(k in tried for k in keys):
            return "exhausted — already run"

        return "available"
