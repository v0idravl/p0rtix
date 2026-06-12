"""
The scheduler — the engine kernel.

It owns the run queue and the tried/inflight bookkeeping, dispatches Actions,
flushes their per-action buffer into the shared Findings, and re-evaluates
availability whenever a new fact arrives. The "circle back on a new fact"
behaviour that today only exists at coarse phase boundaries lives here, per
protocol and event-driven.

Phase 0 runs synchronously (deterministic for tests); a `ThreadPoolExecutor`
worker pool slots in behind the same `dispatch`/`_on_done` seam in Phase 1.

Re-entrancy rule: `_on_fact` (a FactStore subscriber) must be cheap and must
NOT dispatch — it only marks the availability cache dirty. A handler runs while
emitting facts, so dispatching from inside `_on_fact` would re-enter mid-action.
`run_all_at_or_below` instead recomputes availability in a loop, so the unlock
cascade emerges without re-entrant dispatch.
"""
from __future__ import annotations

import json
import threading
from collections import deque

from lib.engine.action import Action, ActionContext, ActionResult
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.registry import ActionRegistry, instance_key
from lib.findings import ServiceBuffer

_STATE_FILE = "engine_state.json"


class Scheduler:
    def __init__(
        self,
        registry: ActionRegistry,
        facts: FactStore,
        posture: Posture,
        *,
        ip: str = "",
        domain: str | None = None,
        runner=None,
        findings=None,
        tools: set[str] | None = None,
        on_output=None,
    ):
        self._registry = registry
        self._facts = facts
        self._posture = posture
        self._ip = ip
        self._domain = domain
        self._runner = runner
        self._findings = findings
        self._tools = tools
        # Optional UI sink: called as on_output(action_name, summary, rendered_md)
        # after each action completes, so a console can stream results inline.
        self._on_output = on_output

        self._lock = threading.Lock()
        self._queue: deque[tuple[Action, dict]] = deque()
        self._queued: set[str] = set()
        self._tried: set[str] = set()
        self._completed: list[tuple[str, dict]] = []   # chronological, for ordering
        self._dirty = True

        self._load_state()
        facts.subscribe(self._on_fact)

    # ── fact subscription (cheap; never dispatches) ───────────────────────────
    def _on_fact(self, _ev) -> None:
        self._dirty = True

    # ── enqueue / step (manual, queue-driven) ─────────────────────────────────
    def enqueue(self, action: Action, args: dict) -> bool:
        key = instance_key(action.name, args)
        with self._lock:
            if key in self._tried or key in self._queued:
                return False
            self._queue.append((action, args))
            self._queued.add(key)
            return True

    def step(self) -> ActionResult | None:
        """Dispatch one queued instance. Returns its result, or None if idle."""
        with self._lock:
            if not self._queue:
                return None
            action, args = self._queue.popleft()
            self._queued.discard(instance_key(action.name, args))
        return self.dispatch(action, args)

    def drain(self) -> int:
        """Run the queue to empty. Returns the number of instances dispatched."""
        n = 0
        while self.step() is not None:
            n += 1
        return n

    # ── dispatch one instance (synchronous core) ──────────────────────────────
    def dispatch(self, action: Action, args: dict) -> ActionResult:
        key = instance_key(action.name, args)
        with self._lock:
            if key in self._tried:
                return ActionResult(ok=True, summary="already run")
            self._tried.add(key)        # mark at dispatch so it can't re-enqueue

        port = args.get("port") if args else None
        buf = ServiceBuffer(port or 0, "tcp")
        ctx = ActionContext(
            ip=self._ip, domain=self._domain, runner=self._runner,
            facts=self._facts, findings=buf,
            available=self._tools or set(), target_port=port, args=args or {},
        )
        try:
            result = action.handler(ctx) or ActionResult()
        except Exception as exc:   # a handler failure must not kill the engine
            buf.note(f"Action error: {exc}")
            result = ActionResult(ok=False, summary=str(exc))

        self._on_done(action, args, buf, result)
        return result

    def _on_done(self, action: Action, args: dict, buf: ServiceBuffer, result) -> None:
        rendered = buf.render()
        if self._findings is not None:
            self._findings.flush_service_buffer(buf)
        self._completed.append((action.name, args))
        self._save_state()
        if self._on_output is not None:
            try:
                self._on_output(action.name, getattr(result, "summary", ""), rendered)
            except Exception:   # a UI sink must never break the engine
                pass

    # ── run-all (cascading, bounded by posture) ───────────────────────────────
    def run_all_at_or_below(self, posture: Posture | None = None) -> int:
        """Dispatch every not-yet-tried available action at or below the posture
        ceiling, cascading on facts unlocked mid-run until quiescent. Returns the
        number dispatched. This is the `auto` / `run-all` thoroughness guarantee."""
        posture = posture or self._posture
        dispatched = 0
        while True:
            avail = [(a, args) for a, args
                     in self._registry.available(self._facts, posture, self._tried, self._tools)
                     if not a.manual_only]                 # never auto-run these
            if not avail:
                break
            for action, args in avail:
                # availability can change as we go; re-check the instance is untried
                if instance_key(action.name, args) in self._tried:
                    continue
                self.dispatch(action, args)
                dispatched += 1
        return dispatched

    def _rearm_for_rerun(self, action: Action, port: int | None = None) -> bool:
        """Drop the tried-state for an action's instance(s) so an *explicit* run
        repeats it. Bulk runs (run-all / run-group) never call this, so they still
        skip completed work — only a deliberate `run <action>` re-runs. Returns
        True if anything was actually re-armed (i.e. this is a genuine re-run)."""
        target = instance_key(action.name, {"port": port}) if port is not None else None
        with self._lock:
            cleared = {k for k in self._tried
                       if k.split("#", 1)[0] == action.name
                       and (target is None or k == target)}
            self._tried -= cleared
        if cleared:
            self._save_state()
        return bool(cleared)

    def run_action(self, name: str, posture: Posture | None = None,
                   *, port: int | None = None) -> int:
        """Dispatch available instances of one named action. With `port`, dispatch
        only the instance for that port (e.g. version-detect a single service).

        An explicit run repeats a previously-run action (manual override) — the
        tried-state is re-armed first, and the runner re-executes (no cached
        output) for the re-run, so `run <action>` always does the thing fresh."""
        posture = posture or self._posture
        action = self._registry.get(name)
        if action is None:
            return 0
        rerun = self._rearm_for_rerun(action, port)
        if rerun and self._runner is not None:
            self._runner.fresh = True
        n = 0
        try:
            for a, args in self._registry.available(self._facts, posture, self._tried, self._tools):
                if a.name != name:
                    continue
                if port is not None and args.get("port") != port:
                    continue
                self.dispatch(a, args)
                n += 1
        finally:
            if rerun and self._runner is not None:
                self._runner.fresh = False
        return n

    def run_group(self, group: str, posture: Posture | None = None) -> int:
        """Dispatch every currently-available action in one path group — the
        'run a bulk of this branch' affordance, between a single action and
        run-all. Cascades like run-all as facts unlock within the group."""
        posture = posture or self._posture
        dispatched = 0
        while True:
            avail = [(a, args) for a, args
                     in self._registry.available(self._facts, posture, self._tried, self._tools)
                     if a.group == group and not a.manual_only]
            if not avail:
                break
            for a, args in avail:
                if instance_key(a.name, args) not in self._tried:
                    self.dispatch(a, args)
                    dispatched += 1
        return dispatched

    # ── overrides / introspection ─────────────────────────────────────────────
    def recheck_users(self) -> None:
        """Clear the collect-once gate so user-list actions re-arm (manual override)."""
        self._facts.users_complete = False
        self._dirty = True

    def recheck(self, proto: str) -> int:
        """Re-arm a dormant branch (operator override): forget the protocol's
        status and drop the tried-state of every action in that group, so they
        become runnable again. Returns the number of actions re-armed."""
        self._facts.clear_proto_status(proto)
        group_actions = {a.name for a in self._registry.all() if a.group == proto}
        with self._lock:
            self._tried = {k for k in self._tried
                           if k.split("#", 1)[0] not in group_actions}
        self._dirty = True
        self._save_state()
        return len(group_actions)

    def reload(self) -> int:
        """Re-read loot files into the fact store (picks up external edits)."""
        return self._facts.reload()

    def status(self) -> dict:
        with self._lock:
            return {
                "tried": len(self._tried),
                "queued": len(self._queue),
                "completed": len(self._completed),
                "level": self._posture.level.label,
            }

    @property
    def tried(self) -> set[str]:
        return set(self._tried)

    @property
    def completed(self) -> list[tuple[str, dict]]:
        return list(self._completed)

    # ── persistence (thin cross-session resume of the tried set) ──────────────
    def _state_path(self):
        return self._facts.machine_dir / _STATE_FILE

    def _save_state(self) -> None:
        try:
            self._state_path().write_text(json.dumps({"tried": sorted(self._tried)}, indent=2))
        except OSError:
            pass

    def _load_state(self) -> None:
        path = self._state_path()
        if path.exists():
            try:
                data = json.loads(path.read_text())
                self._tried = set(data.get("tried", []))
            except (OSError, ValueError):
                self._tried = set()
