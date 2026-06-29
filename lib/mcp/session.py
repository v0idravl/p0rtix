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

# Cap on the aggregated findings markdown returned in a single MCP tool result.
# A broad green sweep (run_all/run_group) concatenates every sub-action's rendered
# markdown; on CozyHosting this reached ~132 KB and overflowed the MCP tool-result
# token limit, erroring the whole call. We hard-cap the concatenated markdown so a
# broad sweep can never overflow. The compact `actions` list (action+summary) and
# `facts_delta` are NEVER truncated, so the caller keeps the full map of what ran
# and can pull a single branch's full detail with run_action(name) / get_state.
_FINDINGS_MD_BUDGET = 48_000  # chars (~12k tokens), well under the tool cap

# Snapshot keys whose values are flat lists of comparable items, diffed by set.
_LIST_KEYS = ("users", "creds", "valid_creds", "admin_pairs",
              "hostnames", "open_ports", "cred_pairs", "cred_must_change")


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

    # web_tech: list of dicts keyed by (port, tech)
    seen_w = {(x["port"], x["tech"]) for x in before.get("web_tech", [])}
    new_w = [x for x in after.get("web_tech", [])
             if (x["port"], x["tech"]) not in seen_w]
    if new_w:
        delta["web_tech"] = new_w

    # upload_endpoints: list of dicts keyed by url
    seen_ue = {x["url"] for x in before.get("upload_endpoints", [])}
    new_ue = [x for x in after.get("upload_endpoints", [])
              if x["url"] not in seen_ue]
    if new_ue:
        delta["upload_endpoints"] = new_ue

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
        # ordered capture log of every action that completed, so a bulk run
        # (run_group / run_all) can aggregate the rendered findings + summaries
        # of *all* its sub-actions — not just the last. This is what makes web
        # enum (and any branch) visible through the MCP response, per doctrine.
        self._captures: list[dict] = []
        # background full-TCP sweep bookkeeping (see start_full_scan)
        self._bg_thread: threading.Thread | None = None
        self._bg_state: dict | None = None
        self.bundle = build_engine(ip, domain, name, args, available,
                                   on_output=self._capture)
        self.ip = ip
        self.domain = domain
        self.available = set(available)
        self._store = None
        try:
            from dagar_state.store import EngagementStore
            self._store = EngagementStore(name or ip)
        except ImportError:
            pass

    # ── capture hook (wired into the scheduler) ───────────────────────────────
    def _capture(self, action_name: str, summary: str, rendered_md: str) -> None:
        entry = {"action": action_name, "summary": summary or "", "rendered": rendered_md or ""}
        self._last[action_name] = entry
        self._captures.append(entry)

    def _collect(self, start: int) -> dict:
        """Aggregate everything captured since index `start`: concatenated
        findings markdown (hard-capped at `_FINDINGS_MD_BUDGET` so a broad bulk run
        can't overflow the MCP tool-result token cap) and a per-action
        [{action, summary}] list (never truncated). When the markdown is capped,
        `findings_truncated` is True and `findings_chars` is the full length so the
        caller knows to pull a branch's detail via run_action(name)/get_state."""
        caps = self._captures[start:]
        md = "\n\n".join(c["rendered"] for c in caps if c["rendered"].strip())
        actions = [{"action": c["action"], "summary": c["summary"]} for c in caps]
        full = len(md)
        truncated = full > _FINDINGS_MD_BUDGET
        if truncated:
            md = md[:_FINDINGS_MD_BUDGET].rstrip() + (
                f"\n\n… [findings truncated — {full} chars total, showing the first "
                f"{_FINDINGS_MD_BUDGET}. The `actions` list maps every sub-action that "
                "ran; pull a branch's full detail with run_action(<name>) or get_state.]")
        return {"findings_md": md, "actions": actions,
                "findings_truncated": truncated, "findings_chars": full}

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
        from lib.engine.exploit_hints import candidates
        snap = self.facts.snapshot()
        out = {
            "target": snap["ip"],
            "domain": snap["domain"],
            "posture": self.posture.level.label,
            "red_unlocked": self.posture.red_unlocked(),
            "breadth": self.facts.breadth.label,
            "open_ports": [list(p) for p in snap["open_ports"]],
            "services": snap["services"],
            "web_tech": snap["web_tech"],
            "upload_endpoints": snap["upload_endpoints"],
            "exploit_candidates": candidates(snap["services"]),
            "background": self._bg_snapshot(),
            "scanned_tcp": snap["scanned_tcp"],
            "users": snap["users"],
            "users_complete": snap["users_complete"],
            "cred_candidates": snap["creds"],
            "valid_creds": [list(c) for c in snap["valid_creds"]],
            "admin_creds": [list(c) for c in snap["admin_pairs"]],
            "cred_pairs": [list(c) for c in snap["cred_pairs"]],
            # credentials that are valid but require a password change before use
            "cred_must_change": [list(c) for c in snap["cred_must_change"]],
            "hashes": snap["hashes"],
            "hostnames": snap["hostnames"],
            "lockout": snap["lockout"],
            "smb_signing_required": snap["smb_signing_required"],
            "proto_status": snap["proto_status"],
            "actions": self.scheduler.status(),
        }
        # Stale-scan warning: the session has scan coverage recorded but no open
        # ports — the scan ran against a now-terminated instance. All service-gated
        # actions remain dormant forever waiting for port facts that won't arrive.
        # Call recheck('discovery') to re-arm discovery, then run_all() to rescan.
        if snap["scanned_tcp"] > 0 and not snap["open_ports"]:
            out["stale_scan_warning"] = (
                "STALE SCAN: scanned_tcp={} but open_ports is empty — the scan "
                "ran against a terminated instance. Call recheck('discovery') to "
                "re-arm discovery actions, then run_all() to re-scan the live "
                "instance. (Or call reload() first if loot files from this "
                "instance are still valid.)".format(snap["scanned_tcp"])
            )
        return out

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
            start = len(self._captures)
            n = self.scheduler.run_action(name, port=port, extra_args=args)
            after = self.facts.snapshot()
            collected = self._collect(start)
        if not n:
            return {
                "ok": False, "dispatched": 0,
                "why": self.registry.why(name, self.facts, self.posture,
                                         self.scheduler.tried, self.available),
            }
        cap = self._last.get(name, {})
        return {
            "ok": True,
            "dispatched": n,
            "summary": cap.get("summary", ""),
            "facts_delta": snapshot_diff(before, after),
            # aggregated across every dispatched instance (e.g. web.enum per port)
            "findings_md": collected["findings_md"],
            "findings_truncated": collected["findings_truncated"],
        }

    def _group_why(self, group: str) -> list[dict]:
        """Per-action state/why for one group — what a bulk run did NOT run and
        why (dormant/blocked/exhausted), so dispatched:0 is explained, not silent."""
        tried = self.scheduler.tried
        rows = []
        for a in sorted(self.registry.all(), key=lambda x: (x.order, x.name)):
            if a.group != group:
                continue
            rows.append({"action": a.name,
                         "why": self.registry.why(a.name, self.facts, self.posture,
                                                  tried, self.available)})
        return rows

    def run_group(self, group: str) -> dict:
        """Dispatch the whole branch (e.g. all SMB sub-actions). Returns the
        aggregated findings markdown and per-action summaries of every sub-action
        dispatched, so a bulk run is never blind through the MCP response. When
        nothing dispatched, `why` explains each action's state (exhausted/blocked/
        dormant) instead of returning a silent dispatched:0."""
        with self._lock:
            if group not in self.registry.group_names():
                return {"ok": False, "error": f"no such group: {group}"}
            before = self.facts.snapshot()
            start = len(self._captures)
            n = self.scheduler.run_group(group)
            after = self.facts.snapshot()
            collected = self._collect(start)
            why = self._group_why(group) if n == 0 else None
        out = {
            "ok": True,
            "dispatched": n,
            "facts_delta": snapshot_diff(before, after),
            "actions": collected["actions"],
            "findings_md": collected["findings_md"],
            "findings_truncated": collected["findings_truncated"],
        }
        if why is not None:
            out["why"] = why
        return out

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
            start = len(self._captures)
            n = self.scheduler.run_all_at_or_below(self.posture)
            after = self.facts.snapshot()
            collected = self._collect(start)
        out = {
            "ok": True,
            "dispatched": n,
            "noise": self.posture.level.label,
            "facts_delta": snapshot_diff(before, after),
            "actions": collected["actions"],
            "findings_md": collected["findings_md"],
            "findings_truncated": collected["findings_truncated"],
        }
        if n == 0:
            out["why"] = (f"nothing runnable at/below '{self.posture.level.label}' noise — "
                          "raise the ceiling (set_noise) or seed a fact (add_fact); "
                          "call list_actions(include_dormant=True) for per-action reasons")
        return out

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

    # ── background full-TCP sweep (delta 4: don't block recon on -p-) ──────────
    def _bg_running(self) -> bool:
        return bool(self._bg_thread is not None and self._bg_thread.is_alive())

    def _bg_snapshot(self) -> dict:
        """Current background-task state for get_state, with liveness refreshed."""
        state = dict(self._bg_state or {})
        if state:
            state["running"] = self._bg_running()
        return state

    def start_full_scan(self) -> dict:
        """Kick a full TCP (-p-) sweep in the background so recon proceeds on the
        quick-scan ports meanwhile. Newly-found ports flow into the fact store
        (poll get_state / background_status). Safe: runs on its own Runner over
        the thread-safe fact store and never holds the session dispatch lock."""
        with self._lock:
            if self._bg_thread is not None and self._bg_thread.is_alive():
                return {"ok": True, "status": "running",
                        "note": "a full TCP sweep is already in progress"}
            self._bg_state = {"kind": "full_tcp_sweep", "running": True, "new_ports": []}
            self._bg_thread = threading.Thread(target=self._full_scan_worker, daemon=True)
            self._bg_thread.start()
        return {"ok": True, "status": "started",
                "note": "full TCP sweep running in background — poll background_status / get_state"}

    def _full_scan_worker(self) -> None:
        from lib import nmap
        from lib.runner import Runner
        try:
            runner = Runner(self.facts)
            before = {p for (pr, p) in self.facts.snapshot()["open_ports"] if pr == "tcp"}
            # Do NOT pass an exclusion list here.  A -p- sweep covers all 65535 ports;
            # the dedup from skipping already-scanned ports saves <0.1% of work, but
            # building --exclude-ports from scanned_tcp() (which grows to 87+ after the
            # quick+common sweeps, or all 65535 after discovery.tcp_ports) can exceed
            # the OS ARG_MAX and cause an [Errno 7] crash that silently kills the sweep.
            ports = nmap.discover_tcp_open(self.ip, runner, self.facts, live=False)
            self.facts.add_scanned_tcp(range(1, 65536))
            for p in ports:
                self.facts.add_open_port("tcp", p)
            self._bg_state = {"kind": "full_tcp_sweep", "running": False, "done": True,
                              "new_ports": sorted(set(ports) - before)}
        except Exception as exc:   # a background failure must never crash the session
            self._bg_state = {"kind": "full_tcp_sweep", "running": False, "done": True,
                              "error": str(exc)}

    def background_status(self) -> dict:
        """Report the background full-TCP sweep: running flag, new_ports found,
        done/error. New ports also appear in get_state's open_ports as they land."""
        return {"ok": True, **self._bg_snapshot()} if self._bg_state \
            else {"ok": True, "running": False, "note": "no background task started"}

    # ── the lab-pwn / metasploit handoff ──────────────────────────────────────
    def export_handoff(self) -> dict:
        """Structured recon inventory for the exploitation/C2 agent.

        Returns a ``hosts[]`` array so the schema composes naturally with
        multi-host handoffs from SessionManager.export_all_handoffs().
        Each host entry carries all recon facts so the consumer can drive
        targeting without re-querying p0rtix.

        Side-effect: syncs discovered hosts, services, and valid creds into the
        dagar-state engagement store when one is open.
        """
        from lib.engine.exploit_hints import candidates
        snap = self.facts.snapshot()
        ip = snap["ip"]

        services = [{"port": s["port"], "proto": s["proto"],
                     "name": s["name"], "version": s["version"]}
                    for s in snap["services"]]
        valid_creds = [{"user": u, "password": p} for u, p in snap["valid_creds"]]

        # Sync to dagar-state when available
        if self._store is not None:
            try:
                self._store.upsert_host(ip, hostname=snap.get("domain") or None)
                for svc in snap["services"]:
                    self._store.add_service(ip, svc["port"], svc["proto"],
                                            service=svc["name"], version=svc["version"])
                for u, p in snap["valid_creds"]:
                    cid = self._store.add_cred(ip, u, p, "password", source="p0rtix")
                    self._store.mark_cred_valid(cid)
            except Exception:
                pass

        host_block = {
            "ip": ip,
            "domain": snap["domain"],
            "hostnames": snap["hostnames"],
            "relay_target": snap["smb_signing_required"] is False,
            "open_ports": [{"proto": pr, "port": po} for pr, po in snap["open_ports"]],
            "services": services,
            "web_tech": snap["web_tech"],
            "upload_endpoints": snap["upload_endpoints"],
            "exploit_candidates": candidates(snap["services"]),
            "valid_creds": valid_creds,
            "admin_creds": [{"user": u, "password": p} for u, p in snap["admin_pairs"]],
            "cred_pairs": [{"user": u, "password": p} for u, p in snap["cred_pairs"]],
            "cred_must_change": [{"user": u, "password": p}
                                 for u, p in snap["cred_must_change"]],
            "hashes": snap["hashes"],
            "users": snap["users"],
        }
        return {
            "hosts": [host_block],
            # top-level flattened fields kept for backwards compat with
            # normalize_ingest() consumers that read the first host's values
            "domain": snap["domain"],
            "full_scan_running": self._bg_running(),
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

    def export_all_handoffs(self) -> dict:
        """Merge handoffs from every open session into a single multi-host dict.

        The ``hosts[]`` array contains one entry per open session so the
        exploitation/C2 agent sees the full engagement surface in one call.
        """
        all_hosts = []
        any_running = False
        for sess in self._sessions.values():
            with sess._lock:
                h = sess.export_handoff()
            all_hosts.extend(h.get("hosts", []))
            if h.get("full_scan_running"):
                any_running = True
        return {
            "hosts": all_hosts,
            "full_scan_running": any_running,
        }
