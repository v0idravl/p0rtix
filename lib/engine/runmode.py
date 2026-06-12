"""
`--mode console` entry point.

Wires the engine together for one target — FactStore (the event-emitting
workspace), Runner, the built-in action registry, the noise posture from
`--level`, and the scheduler — then hands control to the console. The console
opens at PASSIVE (zero packets); the dial drives any launch-time autorun.
"""
from __future__ import annotations

from lib import ui
from lib.engine.actions_builtin import build_registry
from lib.engine.console import run_console
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler
from lib.findings import Findings
from lib.logger import setup_logging
from lib.runner import Runner


def run_console_mode(ip: str, domain: str | None, name: str | None,
                     args, available: set[str]) -> None:
    facts = FactStore(ip, domain, name, args.workspace)
    facts.deep = args.deep
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
    posture = Posture(dial=args.level)
    scheduler = Scheduler(
        registry, facts, posture,
        ip=ip, domain=domain, runner=runner, findings=findings, tools=available,
    )

    ui.info(f"Console   : {facts.machine_dir}")
    ui.info(f"Findings  : {facts.findings_path}")
    ui.info(f"Posture   : passive (dial {args.level})")
    try:
        run_console(scheduler, registry, facts, posture,
                    headless=getattr(args, "headless", False))
    finally:
        findings.finalize()
        from p0rtix import _chown
        _chown(facts)
