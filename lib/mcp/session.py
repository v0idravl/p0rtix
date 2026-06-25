"""
The MCP session — one wired engine per target, with a generic tool surface.

`McpSession` mirrors the engine the way the human console's `CommandRouter` does,
but returns structured data instead of text. Every method maps to an existing
engine call; no recon logic is re-encoded here, so a new `register()` in
`actions_builtin.py` is callable over MCP for free (via `list_actions` /
`run_action`) with no change in this file.

Results are computed by snapshotting `facts` before and after a dispatch and
diffing the structured snapshot — that diff *is* the `facts_delta` an agent acts
on. The per-action rendered markdown comes from the scheduler's existing
`on_output` callback. A single per-session lock serialises engine mutation so two
concurrent tool calls can't interleave dispatches.

This module has no dependency on the MCP SDK; `server.py` wraps it.
"""
from __future__ import annotations

import threading

from lib.engine.action import Tier
from lib.engine.runmode import build_engine

# label → Tier ("passive"/"green"/"yellow"/"red"), same mapping the console uses.
_TIER_BY_NAME = {t.label: t for t in Tier}

# Snapshot keys whose values are flat lists of comparable items, diffed by set.
_LIST_KEYS = ("users", "creds", "valid_creds", "admin_pairs",
              "hostnames", "open_ports", "cred_pairs")


def _freeze(x):
    """Hashable identity for a snapshot entry (lists/tuples → tuple)."""
    if isinstance(x, (list, tuple)):
        return tuple(_freeze(i) for i in x)
    return x


def _jsonify(x):
    """Tuples → lists, recursively, so a value is JSON-safe."""
    if isinstance(x, tuple):
        return [_jsonify(i) for i in x]
    if isinstance(x, list):
        return [_jsonify(i) for i in x]
    return x


def snapshot_diff(before: dict, after: dict) -> dict:
    """What facts appeared/changed between two `FactStore.snapshot()` calls.

    Returns only the new/changed entries, JSON-safe. This is the structured
    signal an agent reacts to after running an action."""
    delta: dict = {}
    for k in _LIST_KEYS:
        seen = {_freeze(x) for x in before.get(k, [])}
        new = [_jsonify(x) for x in after.get(k, []) if _freeze(x) not in seen]
        if new:
            delta[k] = new

    # hashes: list of dicts keyed by (kind, principal, cracked)
    seen_h = {(h["kind"], h["principal"], h["cracked"]) for h in before.get("hashes", [])}
    new_h = [h for h in after.get("hashes", [])
             if (h["kind"], h["principal"], h["cracked"]) not in seen_h]
    if new_h:
        delta["hashes"] = new_h

    # services: list of dicts keyed by (proto, port, name, version)
    seen_s = {(x["proto"], x["port"], x["name"], x["version"])
              for x in before.get("services", [])}
    new_s = [x for x in after.get("services", [])
             if (x["proto"], x["port"], x["name"], x["version"]) not in seen_s]
    if new_s:
        delta["services"] = new_s

    # proto_status: report keys whose status changed
    bs, as_ = before.get("proto_status", {}), after.get("proto_status", {})
    changed = {k: v for k, v in as_.items() if bs.get(k) != v}
    if changed:
        delta["proto_status"] = changed

    # scalar facts that flip from empty → set
    if not before.get("domain") and after.get("domain"):
        delta["domain"] = after["domain"]
    if before.get("lockout") == -1 and after.get("lockout") != -1:
        delta["lockout"] = after["lockout"]

    return delta


class McpSession:
    """One target's engine, exposed as structured tool calls."""

    def __init__(self, ip: str, domain: str | None, name: str | None,
                 args, available: set[str]):
        self._lock = threading.Lock()
        # per-action capture: name → {"summary", "rendered"}
        self._last: dict[str, dict] = {}
        self.bundle = build_engine(ip, domain, name, args, available,
                                   on_output=self._capture)
        self.ip = ip
        self.domain = domain
        self.available = set(available)

    # ── capture hook (wired into the scheduler) ───────────────────────────────
    def _capture(self, action_name: str, summary: str, rendered_md: str) -> None:
        self._last[action_name] = {"summary": summary or "", "rendered": rendered_md or ""}

    # convenience accessors
    @property
    def facts(self):
        return self.bundle.facts

    @property
    def scheduler(self):
        return self.bundle.scheduler

    @property
    def registry(self):
        return self.bundle.registry

    @property
    def posture(self):
        return self.bundle.posture

    # ── inspection ────────────────────────────────────────────────────────────
    def get_state(self) -> dict:
        """Authoritative engine state: facts snapshot + scheduler status."""
        snap = self.facts.snapshot()
        return {
            "target": snap["ip"],
            "domain": snap["domain"],
            "posture": self.posture.level.label,
            "red_unlocked": self.posture.red_unlocked(),
            "breadth": self.facts.breadth.label,
            "open_ports": [list(p) for p in snap["open_ports"]],
            "services": snap["services"],
            "scanned_tcp": snap["scanned_tcp"],
            "users": snap["users"],
            "users_complete": snap["users_complete"],
            "cred_candidates": snap["creds"],
            "valid_creds": [list(c) for c in snap["valid_creds"]],
            "admin_creds": [list(c) for c in snap["admin_pairs"]],
            "cred_pairs": [list(c) for c in snap["cred_pairs"]],
            "hashes": snap["hashes"],
            "hostnames": snap["hostnames"],
            "lockout": snap["lockout"],
            "smb_signing_required": snap["smb_signing_required"],
            "proto_status": snap["proto_status"],
            "actions": self.scheduler.status(),
        }

    def list_actions(self, include_dormant: bool = True) -> list[dict]:
        """Every action with its planning state — the agent's catalogue.

        `state` is available | blocked | dormant | exhausted (from the registry's
        by-path view). `why` is the one-line reason. `instances` is the runnable
        instance count for available actions (e.g. one version-detect per port)."""
        tried = self.scheduler.tried
        grouped = self.registry.grouped(self.facts, self.posture, tried, self.available)
        rows: list[dict] = []
        for group, items in grouped:
            for action, state, info in items:
                if not include_dormant and state in ("dormant", "exhausted"):
                    continue
                rows.append({
                    "name": action.name,
                    "group": group,
                    "tier": action.tier.label,
                    "state": state,
                    "footprint": action.footprint.summary,
                    "deps": list(action.deps),
                    "manual_only": action.manual_only,
                    "instances": info if (state == "available" and isinstance(info, int)) else None,
                    "why": self.registry.why(action.name, self.facts, self.posture,
                                             tried, self.available),
                })
        return rows

    # ── execution ─────────────────────────────────────────────────────────────
    def run_action(self, name: str, port: int | None = None,
                   args: dict | None = None) -> dict:
        """Dispatch one action (re-runs fresh if already done). `args` carries
        free-text payloads such as access.exec's `command`."""
        with self._lock:
            if self.registry.get(name) is None:
                return {"ok": False, "error": f"no such action: {name}"}
            before = self.facts.snapshot()
            n = self.scheduler.run_action(name, port=port, extra_args=args)
            after = self.facts.snapshot()
        cap = self._last.get(name, {})
        if not n:
            return {
                "ok": False, "dispatched": 0,
                "why": self.registry.why(name, self.facts, self.posture,
                                         self.scheduler.tried, self.available),
            }
        return {
            "ok": True,
            "dispatched": n,
            "summary": cap.get("summary", ""),
            "facts_delta": snapshot_diff(before, after),
            "findings_md": cap.get("rendered", ""),
        }

    def run_group(self, group: str) -> dict:
        """Dispatch the whole branch (e.g. all SMB sub-actions)."""
        with self._lock:
            if group not in self.registry.group_names():
                return {"ok": False, "error": f"no such group: {group}"}
            before = self.facts.snapshot()
            n = self.scheduler.run_group(group)
            after = self.facts.snapshot()
        return {"ok": True, "dispatched": n, "facts_delta": snapshot_diff(before, after)}

    def run_all(self, noise_ceiling: str | None = None) -> dict:
        """Run everything available at/below the noise ceiling, cascading on new
        facts. Optionally raise the ceiling first."""
        with self._lock:
            if noise_ceiling:
                tier = _TIER_BY_NAME.get(noise_ceiling.lower())
                if tier is None:
                    return {"ok": False, "error": "noise must be passive|green|yellow|red"}
                if tier > self.posture.level and not self.posture.raise_to(tier):
                    return {"ok": False, "error": "RED is locked — call arm_dangerous first"}
            before = self.facts.snapshot()
            n = self.scheduler.run_all_at_or_below(self.posture)
            after = self.facts.snapshot()
        return {
            "ok": True,
            "dispatched": n,
            "noise": self.posture.level.label,
            "facts_delta": snapshot_diff(before, after),
        }

    # ── posture ───────────────────────────────────────────────────────────────
    def set_noise(self, level: str) -> dict:
        tier = _TIER_BY_NAME.get(level.lower())
        if tier is None:
            return {"ok": False, "error": "level must be passive|green|yellow|red"}
        with self._lock:
            if tier > self.posture.level:
                if not self.posture.raise_to(tier):
                    return {"ok": False, "error": "RED is locked — call arm_dangerous first"}
            else:
                self.posture.lower_to(tier)
        return {"ok": True, "noise": self.posture.level.label}

    def arm_dangerous(self) -> dict:
        with self._lock:
            self.posture.arm_dangerous()
        return {"ok": True, "red_unlocked": True}

    def set_breadth(self, level: str) -> dict:
        """Set the concise→broad effort knob (orthogonal to noise). Scales crack
        rule depth today; broader wordlists as more call sites adopt it."""
        from lib.wordlists import parse_breadth
        b = parse_breadth(level, None)
        if b is None:
            return {"ok": False, "error": "breadth must be concise|standard|broad"}
        with self._lock:
            self.facts.breadth = b
        return {"ok": True, "breadth": b.label}

    # ── fact population / overrides ───────────────────────────────────────────
    def add_fact(self, kind: str, value: str) -> dict:
        k = kind.lower()
        with self._lock:
            if k == "user":
                self.facts.add_user(value)
            elif k in ("cred", "creds"):
                if ":" not in value:
                    return {"ok": False, "error": "creds must be 'user:pass'"}
                u, p = value.split(":", 1)
                self.facts.add_valid_cred(u, p, "manual")
            elif k == "domain":
                self.facts.set_discovered_domain(value)
            else:
                return {"ok": False, "error": f"unknown fact kind: {kind} (user|creds|domain)"}
        return {"ok": True, "kind": k, "value": value}

    def reload(self) -> dict:
        with self._lock:
            n = self.scheduler.reload()
        return {"ok": True, "new_facts": n}

    def recheck(self, proto: str | None = None) -> dict:
        with self._lock:
            if not proto or proto.lower() == "users":
                self.scheduler.recheck_users()
                return {"ok": True, "rechecked": "users"}
            n = self.scheduler.recheck(proto.lower())
        return {"ok": True, "rechecked": proto.lower(), "rearmed": n}

    # ── the lab-pwn / metasploit handoff ──────────────────────────────────────
    def export_handoff(self) -> dict:
        """Structured recon inventory for an exploitation agent (metasploitmcp).
        Pure read of the fact store — no exploitation, no shells."""
        snap = self.facts.snapshot()
        return {
            "hosts": [snap["ip"]],
            "domain": snap["domain"],
            "hostnames": snap["hostnames"],
            # relay target when SMB signing is explicitly not required
            "relay_target": snap["smb_signing_required"] is False,
            "open_ports": [{"proto": pr, "port": po} for pr, po in snap["open_ports"]],
            # versioned services drive exploit selection on the metasploit side
            "services": [{"port": s["port"], "proto": s["proto"],
                          "name": s["name"], "version": s["version"]}
                         for s in snap["services"]],
            "valid_creds": [{"user": u, "password": p} for u, p in snap["valid_creds"]],
            "admin_creds": [{"user": u, "password": p} for u, p in snap["admin_pairs"]],
            "cred_pairs": [{"user": u, "password": p} for u, p in snap["cred_pairs"]],
            "hashes": snap["hashes"],
            "users": snap["users"],
        }


class SessionManager:
    """Holds the active recon session(s) so the MCP server can register statically
    (no target at launch) and the agent opens a box with `open_target`. One box at
    a time is the norm; multiple are keyed by ip/name so re-opening resumes. This
    is what lets a single registered `p0rtix-mcp` serve box after box."""

    def __init__(self, args, available):
        self._args = args
        self._available = set(available)
        self._sessions: dict[str, McpSession] = {}
        self._current: McpSession | None = None

    def open(self, ip: str, domain: str | None = None,
             name: str | None = None) -> McpSession:
        key = f"{ip}/{name or ip}"
        sess = self._sessions.get(key)
        if sess is None:
            sess = McpSession(ip, domain, name, self._args, self._available)
            self._sessions[key] = sess
        self._current = sess
        return sess

    @property
    def current(self) -> McpSession | None:
        return self._current

    def targets(self) -> list[str]:
        return sorted(self._sessions)
