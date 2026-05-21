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
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.deps import check_deps
from lib.findings import Findings, ServiceBuffer
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

    # Deduplicate sibling ports that map to the same handler to avoid running
    # identical enumeration twice (e.g. SMB on 139+445, LDAP on 389+3268).
    services = _dedup_services(services)

    # ── Phase 3: Parallel service + web enumeration ───────────────────────────
    print(f"\n[*] Starting parallel enumeration ({len(services)} service(s))...")

    web_services   = [s for s in services if s.is_web]
    other_services = [s for s in services if not s.is_web]

    all_discoveries: list[Discovery] = []
    svc_futures: dict = {}  # future → (ServiceBuffer, label)

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for svc in web_services:
            buf = ServiceBuffer(svc.port, svc.proto)
            f = pool.submit(
                enumerate_web,
                args.ip, svc, args.domain, runner, buf, scope, hosts, available,
            )
            svc_futures[f] = (buf, f"web:{svc.port}")

        for svc in other_services:
            buf = ServiceBuffer(svc.port, svc.proto)
            f = pool.submit(
                enumerate_service,
                args.ip, svc, runner, buf, available,
            )
            svc_futures[f] = (buf, f"service:{svc.port}")

        for future in as_completed(svc_futures):
            buf, label = svc_futures[future]
            try:
                result = future.result()
                if result:
                    all_discoveries.extend(result)
                print(f"[+] Done: {label}")
            except Exception as exc:
                print(f"[!] Error in {label}: {exc}")
                buf.note(f"Enumeration error: {exc}")

    # Flush service buffers to findings in port order (fixes parallel scrambling)
    findings.h2("Service Findings")
    for buf, _ in sorted(svc_futures.values(), key=lambda x: (x[0].port, x[0].proto)):
        findings.flush_service_buffer(buf)

    # ── Phase 3.5: Post-enum domain-dependent checks ──────────────────────────
    # By now all parallel handlers have written to users.txt and set
    # ws.discovered_domain (from LDAP base DN). Run domain-gated checks here
    # with the complete user list instead of mid-scan inside each handler.
    effective_domain = args.domain or ws.discovered_domain
    if ws.discovered_domain and not args.domain:
        print(f"\n[*] Domain discovered: {ws.discovered_domain}")
        if not hosts.resolves(ws.discovered_domain):
            print(f"[*] Domain not in /etc/hosts.")
            hosts.prompt_add(args.ip, ws.discovered_domain)

    if effective_domain:
        _run_post_domain_checks(args.ip, effective_domain, runner, findings, ws, available)

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
            svc = Service(
                port=d.port, proto="tcp", name=d.scheme,
                version="", is_web=True, scheme=d.scheme,
                hostname=d.hostname,
            )
            new_hosts.append((d, svc))

    if new_hosts:
        print(f"\n[*] Follow-up enumeration on {len(new_hosts)} discovered host(s)...")

        followup_futures: dict = {}
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for d, svc in new_hosts:
                buf = ServiceBuffer(svc.port, svc.proto)
                f = pool.submit(
                    enumerate_web,
                    args.ip, svc, args.domain, runner, buf, scope, hosts, available,
                    is_followup=True,
                )
                followup_futures[f] = (buf, d.hostname)

            for future in as_completed(followup_futures):
                buf, label = followup_futures[future]
                try:
                    future.result()
                    print(f"[+] Done: {label}")
                except Exception as exc:
                    print(f"[!] Error in followup {label}: {exc}")
                    buf.note(f"Enumeration error: {exc}")

        findings.h2("Discovered Hosts")
        for buf, _ in sorted(followup_futures.values(), key=lambda x: (x[0].port, x[0].proto)):
            findings.flush_service_buffer(buf)

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


def _run_post_domain_checks(
    ip: str, domain: str, runner: Runner,
    findings: Findings, ws: Workspace, available: set[str],
):
    """
    Domain-gated checks that require the complete users.txt assembled
    across all parallel handlers (LDAP + SMB + enum4linux-ng).
    Runs sequentially after phase 3 so the user list is final.
    """
    users_file = ws.loot_dir / "users.txt"
    if not users_file.exists() or users_file.stat().st_size == 0:
        return

    findings.h2("Post-Enumeration: Domain Checks")
    findings.bullet(f"Domain: `{domain}` — user list: `{users_file}` ({sum(1 for _ in users_file.open())} accounts)")

    # AS-REP roasting — full user list, catches accounts LDAP UAC flag missed
    if "impacket-GetNPUsers" in available:
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
            findings.code_block(out.strip())
        else:
            findings.bullet("AS-REP roasting: no vulnerable accounts in user list")

    # Kerbrute username validation against the discovered user list
    if "kerbrute" in available:
        cmd2 = ["kerbrute", "userenum", "--dc", ip, "-d", domain, str(users_file)]
        findings.cmd(" ".join(cmd2))
        out2 = runner.run(cmd2, "post_kerbrute_userenum", timeout=300)
        valid = re.findall(r"VALID USERNAME:\s+(\S+)", out2)
        if valid:
            findings.bullet(f"**kerbrute confirmed ({len(valid)} valid):** {', '.join(valid)}")
        else:
            findings.bullet("kerbrute: no additional valid usernames confirmed")

    findings.note(
        f"Kerberoasting (needs creds): "
        f"`impacket-GetUserSPNs {domain}/USER:PASS -dc-ip {ip} -request -outputfile spns.txt`"
    )


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
    if 389 in open_tcp and 3268 in open_tcp:  # LDAP GC mirrors 389 in single-domain forests
        drop.add((3268, "tcp"))
    if 636 in open_tcp and 3269 in open_tcp:  # LDAPS GC mirrors 636
        drop.add((3269, "tcp"))
    if 88 in open_tcp and 88 in open_udp:     # Kerberos: TCP and UDP hit same handler
        drop.add((88, "udp"))
    if 53 in open_udp and 53 in open_tcp:     # DNS: UDP is primary; TCP rarely adds more
        drop.add((53, "tcp"))

    if not drop:
        return services

    for port, proto in sorted(drop):
        print(f"[*] Dedup: skipping {proto.upper()} {port} (covered by sibling port)")
    return [s for s in services if (s.port, s.proto) not in drop]


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
