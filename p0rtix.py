#!/usr/bin/env python3
"""
p0rtix — automated recon and enumeration for CTF / OSCP / pentest labs

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
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.deps import check_deps
from lib.findings import Findings
from lib.hosts import HostsManager
from lib.models import Discovery, Service
from lib.nmap import run_port_discovery, run_service_scan
from lib.runner import Runner
from lib.scope import Scope
from lib.services import enumerate_service
from lib.web import enumerate_web
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
    p.add_argument("ip", help="Target IP address")
    p.add_argument("--domain", "-d", metavar="DOMAIN",
                   help="Primary domain for vhost busting (e.g. test.htb)")
    p.add_argument("--name", "-n", metavar="NAME",
                   help="Machine nickname used for the output directory (default: domain or IP)")
    p.add_argument("--workspace", "-w", metavar="DIR", default=".",
                   help="Root directory for all output (default: current directory)")
    p.add_argument("--workers", type=int, default=6, metavar="N",
                   help="Parallel enumeration threads (default: 6)")
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    if os.geteuid() != 0:
        print("[!] p0rtix requires root — re-run with: sudo python3 p0rtix.py ...")
        sys.exit(1)

    # ── Setup ─────────────────────────────────────────────────────────────────
    available = check_deps()

    ws = Workspace(args.ip, args.domain, args.name, args.workspace)
    findings = Findings(ws.findings_path, args.ip, args.domain)
    runner = Runner(ws)
    hosts = HostsManager()
    scope = Scope(args.ip, args.domain)

    # If a domain was provided and it doesn't resolve yet, offer to add it now
    if args.domain and not hosts.resolves(args.domain):
        print(f"\n[*] Domain '{args.domain}' does not resolve.")
        hosts.prompt_add(args.ip, args.domain)

    print(f"\n[*] Workspace : {ws.machine_dir}")
    print(f"[*] Findings  : {ws.findings_path}")
    print(f"[*] Target    : {args.ip}" + (f"   Domain: {args.domain}" if args.domain else ""))
    print(f"[*] Workers   : {args.workers}")
    print()

    # ── Phase 1: Port discovery ───────────────────────────────────────────────
    ports = run_port_discovery(args.ip, runner, ws, findings)

    if not ports["tcp"] and not ports["udp"]:
        findings.note("No open ports found.")
        print("[!] No open ports found. Exiting.")
        return

    # ── Phase 2: Service version scan + classification ────────────────────────
    services = run_service_scan(args.ip, ports, runner, ws, findings)

    # Attach domain context to all services that need it for AD/Kerberos/DNS enumeration.
    # Handlers read service.hostname to avoid requiring a separate domain argument.
    AD_PORTS = {53, 88, 139, 389, 445, 636, 3268, 3269}
    for svc in services:
        if svc.port in AD_PORTS and args.domain and not svc.hostname:
            svc.hostname = args.domain

    # ── Phase 3: Parallel service + web enumeration ───────────────────────────
    print(f"\n[*] Starting parallel enumeration ({len(services)} service(s))...")
    findings.h2("Service Findings")

    web_services = [s for s in services if s.is_web]
    other_services = [s for s in services if not s.is_web]

    all_discoveries: list[Discovery] = []

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures: dict = {}

        for svc in web_services:
            f = pool.submit(
                enumerate_web,
                args.ip, svc, args.domain, runner, findings, scope, hosts, available,
            )
            futures[f] = f"web:{svc.port}"

        for svc in other_services:
            f = pool.submit(
                enumerate_service,
                args.ip, svc, runner, findings, available,
            )
            futures[f] = f"service:{svc.port}"

        for future in as_completed(futures):
            label = futures[future]
            try:
                result = future.result()
                if result:
                    all_discoveries.extend(result)
                print(f"[+] Done: {label}")
            except Exception as exc:
                print(f"[!] Error in {label}: {exc}")

    # ── Phase 4: Follow-up on discovered vhosts / SSL SANs / redirects ────────
    new_hosts: list[tuple[Discovery, Service]] = []

    for d in all_discoveries:
        if hosts.is_known(d.hostname):
            continue
        if not scope.check(d.hostname):
            print(f"[~] Out of scope — skipping: {d.hostname} (from {d.source})")
            continue

        print(f"\n[*] [{d.type.upper()}] Discovered: {d.hostname}  (via {d.source})")
        if hosts.prompt_add(args.ip, d.hostname):
            # Build a minimal Service for this discovered host
            svc = Service(
                port=d.port, proto="tcp", name=d.scheme,
                version="", is_web=True, scheme=d.scheme,
                hostname=d.hostname,
            )
            new_hosts.append((d, svc))

    if new_hosts:
        print(f"\n[*] Follow-up enumeration on {len(new_hosts)} discovered host(s)...")
        findings.h2("Discovered Hosts")

        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {}
            for d, svc in new_hosts:
                f = pool.submit(
                    enumerate_web,
                    args.ip, svc, args.domain, runner, findings, scope, hosts, available,
                    is_followup=True,
                )
                futures[f] = d.hostname

            for future in as_completed(futures):
                label = futures[future]
                try:
                    future.result()
                    print(f"[+] Done: {label}")
                except Exception as exc:
                    print(f"[!] Error in followup {label}: {exc}")

    # ── searchsploit on nmap XML ───────────────────────────────────────────────
    if "searchsploit" in available:
        nmap_xml = ws.raw_dir / "04_tcp_services.xml"
        if nmap_xml.exists():
            findings.h2("searchsploit")
            cmd = ["searchsploit", "--nmap", str(nmap_xml)]
            out = runner.run(cmd, "searchsploit_nmap")
            findings.cmd(" ".join(cmd))
            _write_searchsploit(out, findings)

    # ── Wrap up ────────────────────────────────────────────────────────────────
    findings.finalize()
    print(f"\n{'=' * 60}")
    print(f"[+] Scan complete")
    print(f"[+] Findings  : {ws.findings_path}")
    print(f"[+] Raw data  : {ws.raw_dir}/")
    print(f"[+] Loot      : {ws.loot_dir}/")
    print(f"{'=' * 60}")


def _write_searchsploit(output: str, findings: Findings):
    lines = [
        l for l in output.splitlines()
        if l.strip() and not l.startswith("-") and "Exploits" not in l and "ShellCodes" not in l
    ]
    if lines:
        for line in lines:
            findings.bullet(line.strip())
    else:
        findings.note("No searchsploit matches.")


if __name__ == "__main__":
    main()
