"""
The command router — UI-independent.

`CommandRouter.dispatch(line)` parses one console line and drives the engine
(scheduler / registry / posture / facts), returning text to display. The Textual
dashboard and the line-mode fallback both call this; no engine logic lives in the
UI, which keeps the command surface fully testable without a terminal.

Commands return a string (possibly multi-line). Unknown input returns a short
hint rather than raising, so a typo never crashes the session.
"""
from __future__ import annotations

import shlex

from lib.engine.action import Tier
from lib.engine.registry import instance_key

_TIER_BY_NAME = {t.label: t for t in Tier}

_GLYPH = {Tier.PASSIVE: "·", Tier.GREEN: "🟢", Tier.YELLOW: "🟡", Tier.RED: "🔴"}

_HELP = """\
commands:
  status                       campaign overview (posture, ports, loot counts)
  facts | ports | hashes       dump the fact store / open ports / captured hashes
  actions [--all]              runnable actions (--all includes dormant/exhausted)
  dormant | exhausted          greyed-out (missing inputs) / already-run actions
  why <action>                 explain an action's state
  run <action> [port]          dispatch one action (optionally one port)
  run <group> | run-all|auto   dispatch a whole branch / everything at/below posture
  noise <green|yellow|red>     raise/lower the noise ceiling
  set domain <d> | add user <u> | creds add <u:p>   populate facts by hand
  reload | recheck users       refresh loot from disk / re-arm user-list actions
  recheck <proto>              re-arm a dormant branch (e.g. recheck ldap)
  shell                        drop to a local shell in the workspace dir
  help | exit"""


class CommandRouter:
    def __init__(self, scheduler, registry, facts, posture):
        self._sched = scheduler
        self._reg = registry
        self._facts = facts
        self._posture = posture

    # ── entry point ───────────────────────────────────────────────────────────
    def dispatch(self, line: str) -> str:
        line = line.strip()
        if not line:
            return ""
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        cmd, args = parts[0].lower(), parts[1:]
        handler = self._COMMANDS.get(cmd)
        if handler is None:
            return f"unknown command: {cmd} (try 'help')"
        return handler(self, args)

    # ── inspection ────────────────────────────────────────────────────────────
    def _cmd_status(self, args) -> str:
        snap = self._facts.snapshot()
        st = self._sched.status()
        lines = [
            f"target   {snap['ip']}" + (f"   domain {snap['domain']}" if snap["domain"] else ""),
            f"posture  {self._posture.level.label}   "
            f"(dial {self._posture.dial}, red {'on' if self._posture.red_unlocked() else 'off'})",
            f"ports    {len(snap['open_ports'])} open",
            f"loot     {len(snap['users'])} users · {len(snap['valid_creds'])} valid creds "
            f"· {len(snap['creds'])} cred candidates",
            f"actions  {st['completed']} run · {st['queued']} queued",
        ]
        if snap["lockout"] != -1:
            lines.append(f"lockout  threshold {snap['lockout']}")
        return "\n".join(lines)

    def _cmd_facts(self, args) -> str:
        snap = self._facts.snapshot()
        out = []
        if snap["users"]:
            out.append("users: " + ", ".join(snap["users"]))
        if snap["valid_creds"]:
            out.append("valid creds: " + ", ".join(f"{u}:{p}" for u, p in snap["valid_creds"]))
        if snap["hostnames"]:
            out.append("hostnames: " + ", ".join(snap["hostnames"]))
        if snap["proto_status"]:
            out.append("status: " + ", ".join(f"{k}={v}" for k, v in snap["proto_status"].items()))
        return "\n".join(out) or "(no facts yet)"

    def _cmd_ports(self, args) -> str:
        ports = self._facts.snapshot()["open_ports"]
        if not ports:
            return "(no open ports — run discovery.tcp_ports)"
        return "  ".join(f"{proto}/{port}" for proto, port in ports)

    def _cmd_hashes(self, args) -> str:
        hashes = self._facts.snapshot()["hashes"]
        if not hashes:
            return "(no hashes captured)"
        uncracked = [h for h in hashes if not h["cracked"]]
        cracked = [h for h in hashes if h["cracked"]]
        lines = []
        if uncracked:
            lines.append("uncracked (run crack.hashes):")
            for h in uncracked:
                lines.append(f"  {h['principal'] or '?'}  [{h['kind']}]")
        if cracked:
            lines.append("cracked:")
            for h in cracked:
                lines.append(f"  {h['principal'] or '?'} : {h['plaintext']}  [{h['kind']}]")
        return "\n".join(lines)

    def _cmd_actions(self, args) -> str:
        show_all = "--all" in args
        avail = self._reg.available(self._facts, self._posture, self._sched.tried)
        lines = [f"{_GLYPH[a.tier]} {instance_key(a.name, args_)}" for a, args_ in avail]
        body = ["available:"] + (lines or ["  (none — raise noise or feed a fact)"])
        if show_all:
            body += self._cmd_dormant(args).splitlines()
            body += self._cmd_exhausted(args).splitlines()
        return "\n".join(body)

    def _cmd_dormant(self, args) -> str:
        rows = self._reg.dormant(self._facts)
        if not rows:
            return "dormant: (none)"
        lines = ["dormant:"]
        for action, missing in rows:
            reason = ", ".join(r.label for r in missing) or "preconditions not met"
            lines.append(f"  {_GLYPH[action.tier]} {action.name} — needs {reason}")
        return "\n".join(lines)

    def _cmd_exhausted(self, args) -> str:
        done = self._reg.exhausted(self._facts, self._sched.tried)
        if not done:
            return "exhausted: (none)"
        return "exhausted:\n" + "\n".join(f"  {a.name}" for a in done)

    def _cmd_why(self, args) -> str:
        if not args:
            return "usage: why <action>"
        return self._reg.why(args[0], self._facts, self._posture, self._sched.tried)

    # ── execution ─────────────────────────────────────────────────────────────
    def _cmd_run(self, args) -> str:
        if not args:
            return "usage: run <action> [port]  |  run <group>"
        name = args[0]
        # `run <group>` dispatches the whole branch (bulk); `run <action>` one step.
        if self._reg.get(name) is None:
            if name in self._reg.group_names():
                n = self._sched.run_group(name)
                return f"ran {n} action(s) in the {name} branch" if n else \
                    f"(no available actions in {name})"
            return f"no such action or group: {name}"
        port = int(args[1]) if len(args) > 1 and args[1].isdigit() else None
        n = self._sched.run_action(name, port=port)
        if n:
            where = f" on port {port}" if port is not None else ""
            return f"dispatched {n} instance(s) of {name}{where}"
        return self._reg.why(name, self._facts, self._posture, self._sched.tried)

    def _cmd_run_all(self, args) -> str:
        n = self._sched.run_all_at_or_below(self._posture)
        return f"ran {n} action(s) at/below {self._posture.level.label}"

    # ── posture ───────────────────────────────────────────────────────────────
    def _cmd_noise(self, args) -> str:
        if not args:
            return f"noise level: {self._posture.level.label}"
        tier = _TIER_BY_NAME.get(args[0].lower())
        if tier is None:
            return "usage: noise <green|yellow|red>"
        if tier > self._posture.level:
            if not self._posture.raise_to(tier):
                return "RED is locked — launch with --level 7+ or `set dangerous on`"
            return f"noise raised to {tier.label}"
        self._posture.lower_to(tier)
        return f"noise lowered to {tier.label}"

    # ── manual fact population ────────────────────────────────────────────────
    def _cmd_set(self, args) -> str:
        if len(args) >= 2 and args[0].lower() == "domain":
            self._facts.set_discovered_domain(args[1])
            return f"domain set: {self._facts.discovered_domain}"
        if len(args) >= 2 and args[0].lower() == "dangerous" and args[1].lower() == "on":
            self._posture.arm_dangerous()
            return "RED unlocked"
        return "usage: set domain <d> | set dangerous on"

    def _cmd_add(self, args) -> str:
        if len(args) >= 2 and args[0].lower() == "user":
            self._facts.add_user(args[1])
            return f"user added: {args[1]}"
        return "usage: add user <name>"

    def _cmd_creds(self, args) -> str:
        if len(args) >= 2 and args[0].lower() == "add" and ":" in args[1]:
            u, p = args[1].split(":", 1)
            self._facts.add_valid_cred(u, p, "manual")
            return f"credential added: {u}"
        return "usage: creds add <user:pass>"

    # ── overrides ─────────────────────────────────────────────────────────────
    def _cmd_reload(self, args) -> str:
        n = self._sched.reload()
        return f"reloaded — {n} new fact(s) from loot/"

    def _cmd_recheck(self, args) -> str:
        if args and args[0].lower() == "users":
            self._sched.recheck_users()
            return "user-list actions re-armed"
        if args:
            proto = args[0].lower()
            n = self._sched.recheck(proto)
            return f"{proto} branch re-armed ({n} action(s))"
        return "usage: recheck users | recheck <proto>"

    def _cmd_shell(self, args) -> str:
        # Local shell in the workspace dir (line-mode path; the dashboard wraps
        # this in App.suspend()).
        from lib.engine import access
        access.local_shell(self._facts.machine_dir)
        return "(returned from shell)"

    def _cmd_help(self, args) -> str:
        return _HELP

    _COMMANDS = {
        "status": _cmd_status,
        "facts": _cmd_facts,
        "ports": _cmd_ports,
        "hashes": _cmd_hashes,
        "actions": _cmd_actions,
        "dormant": _cmd_dormant,
        "exhausted": _cmd_exhausted,
        "why": _cmd_why,
        "run": _cmd_run,
        "run-all": _cmd_run_all,
        "auto": _cmd_run_all,
        "noise": _cmd_noise,
        "set": _cmd_set,
        "add": _cmd_add,
        "creds": _cmd_creds,
        "reload": _cmd_reload,
        "recheck": _cmd_recheck,
        "shell": _cmd_shell,
        "help": _cmd_help,
    }
