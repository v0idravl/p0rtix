"""
`--mode console` entry point + the shared engine-wiring builder.

`build_engine()` assembles one wired engine for a single target — FactStore (the
event-emitting workspace), Runner, the built-in action registry, the noise
posture from `--level`, and the scheduler. Both the console (TUI/headless) and
the MCP server build their session from this one place, so there is no wiring
drift between interfaces. The console opens at PASSIVE (zero packets); the dial
drives any launch-time autorun.
"""
from __future__ import annotations

from dataclasses import dataclass

from lib import ui
from lib.engine.actions_builtin import build_registry
from lib.engine.console import run_console
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler
from lib.findings import Findings
from lib.logger import setup_logging
from lib.runner import Runner


@dataclass
class EngineBundle:
    """One fully-wired engine for a single target. Shared by every interface."""

    facts: FactStore
    runner: Runner
    registry: object        # ActionRegistry
    posture: Posture
    scheduler: Scheduler
    findings: Findings
    available: set


def build_engine(ip: str, domain: str | None, name: str | None,
                 args, available: set[str], *, on_output=None) -> EngineBundle:
    """Wire FactStore → Runner → registry → Posture → Scheduler for one target.

    `on_output(action_name, summary, rendered_md)` is forwarded to the scheduler
    so a caller (the MCP session) can capture per-action results. Returns the
    bundle without launching any UI — the caller decides what to do with it."""
    facts = FactStore(ip, domain, name, args.workspace)
    facts.deep = getattr(args, "deep", False)
    setup_logging(facts.log_dir)

    if domain:
        facts.set_discovered_domain(domain)
    if getattr(args, "users", None):
        try:
            for line in open(args.users):
                if line.strip():
                    facts.add_user(line.strip())
        except OSError as exc:
            ui.warn(f"--users file error: {exc}")

    findings = Findings(facts.findings_path, ip, domain)
    findings.h2("Service Findings")
    runner = Runner(facts)
    registry = build_registry()
    posture = Posture(dial=getattr(args, "level", 0))
    scheduler = Scheduler(
        registry, facts, posture,
        ip=ip, domain=domain, runner=runner, findings=findings, tools=available,
        on_output=on_output,
    )
    return EngineBundle(facts, runner, registry, posture, scheduler, findings, available)


def run_console_mode(ip: str, domain: str | None, name: str | None,
                     args, available: set[str]) -> None:
    bundle = build_engine(ip, domain, name, args, available)

    ui.info(f"Console   : {bundle.facts.machine_dir}")
    ui.info(f"Findings  : {bundle.facts.findings_path}")
    ui.info(f"Posture   : passive (dial {getattr(args, 'level', 0)})")
    try:
        run_console(bundle.scheduler, bundle.registry, bundle.facts, bundle.posture,
                    headless=getattr(args, "headless", False))
    finally:
        bundle.findings.finalize()
        from p0rtix import _chown
        _chown(bundle.facts)
