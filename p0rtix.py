#!/usr/bin/env python3
"""
p0rtix — stealthy, coverage-focused recon and enumeration

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
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from lib.analyze import analyze_findings
from lib.deps import check_deps
from lib.findings import Findings, ServiceBuffer, set_verbose
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
    p.add_argument("--analyze", "-A", action="store_true",
                   help="send findings.md to Claude API for AI analysis (requires ANTHROPIC_API_KEY; use sudo -E to preserve env)")
    p.add_argument("--model", default="claude-sonnet-4-6", metavar="MODEL",
                   help="Claude model for --analyze (default: claude-sonnet-4-6)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="show inline notes and searchsploit results in findings.md")
    p.add_argument("--mode", default="scan",
                   help="scan = full recon (default); creds = credentialed AD enum; scan,creds = both in one run")
    p.add_argument("-u", "--username", metavar="USER",
                   help="Single username for --mode creds")
    p.add_argument("-p", "--password", metavar="PASS",
                   help="Single password for --mode creds")
    p.add_argument("--creds", metavar="FILE",
                   help="File of username:password pairs (one per line) for --mode creds")
    return p.parse_args()


def main():
    print(BANNER)
    args = parse_args()

    if os.geteuid() != 0:
        print("[!] p0rtix requires root — re-run with: sudo python3 p0rtix.py ...")
        sys.exit(1)

    _VALID_MODES = {"scan", "creds", "scan,creds"}
    if args.mode not in _VALID_MODES:
        sys.exit(f"[!] Invalid --mode '{args.mode}'. Choose: scan | creds | scan,creds")

    _needs_creds = args.mode in ("creds", "scan,creds")
    if _needs_creds and not args.username and not args.creds:
        sys.exit("[!] --mode creds/scan,creds requires -u/-p or --creds <file>")
    if _needs_creds and not args.domain:
        print("[!] Warning: --domain not set; AD tools will have limited scope")

    # ── Setup ─────────────────────────────────────────────────────────────────
    available = check_deps()

    ws = Workspace(args.ip, args.domain, args.name, args.workspace,
                   mode="scan" if args.mode == "scan,creds" else args.mode)
    findings = Findings(ws.findings_path, args.ip, args.domain)
    set_verbose(args.verbose)
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

    # ── Creds-only mode dispatch (scan,creds runs creds phase after scan below) ─
    if args.mode == "creds":
        from lib.credsmode import load_creds, run_creds_mode
        from lib.nmap import parse_service_xml

        creds = load_creds(args.username, args.password, args.creds)
        if not creds:
            sys.exit("[!] No valid credentials parsed from provided input.")

        services: list = []
        tcp_xml = next(ws.raw_dir.glob("*_tcp_services.xml"), None)
        udp_xml = next(ws.raw_dir.glob("*_udp_confirmed.xml"), None)
        if tcp_xml:
            services.extend(parse_service_xml(tcp_xml, "tcp"))
            print(f"[*] Loaded {len(services)} TCP services from {tcp_xml.name}")
        if udp_xml:
            udp_svcs = parse_service_xml(udp_xml, "udp")
            services.extend(udp_svcs)
            if udp_svcs:
                print(f"[*] Loaded {len(udp_svcs)} UDP services from {udp_xml.name}")
        if not services:
            print("[!] No prior nmap XML found — per-service enumeration will be skipped")

        run_creds_mode(args.ip, args.domain, creds, services, runner, findings, ws, available)

        findings.finalize()
        if args.analyze:
            analyze_findings(ws, args.ip, args.domain, model=args.model, mode="creds")
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            subprocess.run(["chown", "-R", f"{sudo_user}:", str(ws.machine_dir)],
                           capture_output=True)
        sys.exit(0)

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

    # ── Phase 3.6: Credential re-use ──────────────────────────────────────────
    creds_file = ws.loot_dir / "creds_found.txt"
    users_file = ws.loot_dir / "users.txt"
    if creds_file.exists() and users_file.exists() and creds_file.stat().st_size > 0:
        _run_cred_reuse(args.ip, runner, findings, ws, services, available)

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

    # ── Loot summary ──────────────────────────────────────────────────────────
    users_file = ws.loot_dir / "users.txt"
    creds_file = ws.loot_dir / "creds_found.txt"
    user_count = (
        sum(1 for _ in users_file.open())
        if users_file.exists() and users_file.stat().st_size > 0 else 0
    )
    cred_count = (
        sum(1 for _ in creds_file.open())
        if creds_file.exists() and creds_file.stat().st_size > 0 else 0
    )
    if user_count or cred_count:
        findings.h2("Loot")
        if user_count:
            findings.bullet(f"**{user_count} unique user(s)** — `{users_file}`")
        if cred_count:
            findings.bullet(f"**{cred_count} credential(s)** — `{creds_file}`")

    # ── searchsploit on nmap XML ───────────────────────────────────────────────
    if args.verbose and "searchsploit" in available:
        nmap_xml = ws.raw_dir / "04_tcp_services.xml"
        if nmap_xml.exists():
            findings.h2("searchsploit")
            cmd = ["searchsploit", "--nmap", str(nmap_xml)]
            out = runner.run(cmd, "searchsploit_nmap")
            findings.cmd(" ".join(cmd))
            _write_searchsploit(out, findings)

    # ── Combined mode: run credentialed phase after scan ─────────────────────
    if args.mode == "scan,creds":
        from lib.credsmode import load_creds, run_creds_mode
        creds_list = load_creds(args.username, args.password, args.creds)
        if creds_list:
            print(f"\n[*] Combined mode: starting credentialed phase as {creds_list[0][0]}...")
            run_creds_mode(args.ip, args.domain, creds_list, services, runner, findings, ws, available)
        else:
            print("[!] Combined mode: no valid credentials — skipping creds phase")

    # ── Wrap up ────────────────────────────────────────────────────────────────
    findings.finalize()
    if args.analyze:
        analyze_findings(ws, args.ip, args.domain, model=args.model)

    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        subprocess.run(["chown", "-R", f"{sudo_user}:", str(ws.machine_dir)],
                       capture_output=True)

    _print_loot_summary(ws)
    print(f"[+] Findings  : {ws.findings_path}")
    print(f"[+] Raw data  : {ws.raw_dir}/")
    print(f"[+] Loot      : {ws.loot_dir}/")
    print("─" * 60)


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
            hash_file = ws.loot_dir / "asrep.hash"
            with open(hash_file, "a") as hf:
                for line in out.splitlines():
                    if "$krb5asrep$" in line:
                        hf.write(line.strip() + "\n")
            findings.bullet(f"**Hash saved:** `{hash_file}` — `hashcat -m 18200 {hash_file} /usr/share/wordlists/rockyou.txt`")
            findings.add_summary(f"**AS-REP hash(es) in `loot/asrep.hash`** — crack: `hashcat -m 18200`")

    # Kerbrute username validation against the discovered user list
    if "kerbrute" in available:
        cmd2 = ["kerbrute", "userenum", "--dc", ip, "-d", domain, str(users_file)]
        findings.cmd(" ".join(cmd2))
        out2 = runner.run(cmd2, "post_kerbrute_userenum", timeout=300)
        valid = re.findall(r"VALID USERNAME:\s+(\S+)", out2)
        if valid:
            findings.bullet(f"**kerbrute confirmed ({len(valid)} valid):** {', '.join(valid)}")

    findings.note(
        f"Kerberoasting (needs creds): "
        f"`impacket-GetUserSPNs {domain}/USER:PASS -dc-ip {ip} -request -outputfile spns.txt`"
    )


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

    open_tcp = {s.port for s in services if s.proto == "tcp"}

    for password in passwords:
        if "nxc" not in available:
            break

        if 445 in open_tcp:
            cmd = [
                "nxc", "smb", ip,
                "-u", str(users_file), "-p", password,
                "--continue-on-success",
            ]
            out = runner.run(cmd, f"cred_smb_{re.sub(r'[^a-z0-9]', '_', password.lower())[:16]}", timeout=120)
            findings.cmd(" ".join(cmd))
            for line in out.splitlines():
                if "[+]" in line:
                    if "Pwn3d!" in line:
                        findings.bullet(f"**ADMIN access via SMB:** `{line.strip()}`")
                        findings.add_summary(f"**Admin SMB shell** with `{password}` — `psexec`/`wmiexec`")
                    else:
                        findings.bullet(f"**Valid SMB credential:** `{line.strip()}`")
                        findings.add_summary(f"Valid SMB credential: `{password}`")
                    _save_valid_cred(ws, line.strip(), password)

        if 5985 in open_tcp:
            cmd2 = [
                "nxc", "winrm", ip,
                "-u", str(users_file), "-p", password,
                "--continue-on-success",
            ]
            out2 = runner.run(cmd2, f"cred_winrm_{re.sub(r'[^a-z0-9]', '_', password.lower())[:16]}", timeout=120)
            findings.cmd(" ".join(cmd2))
            for line in out2.splitlines():
                if "[+]" in line:
                    findings.bullet(f"**Valid WinRM credential (shell!):** `{line.strip()}`")
                    findings.add_summary(
                        f"**WinRM shell** with `{password}` — "
                        f"`evil-winrm -i {ip} -u USER -p {password}`"
                    )
                    _save_valid_cred(ws, line.strip(), password)


def _print_dir_tree(path, prefix: str = "", max_depth: int = 4, depth: int = 0):
    if depth >= max_depth:
        return
    try:
        entries = sorted(path.iterdir(), key=lambda e: (e.is_file(), e.name))
    except PermissionError:
        return
    for i, entry in enumerate(entries):
        connector = "└── " if i == len(entries) - 1 else "├── "
        print(f"        {prefix}{connector}{entry.name}")
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
                print(f"        {u}")
            if len(users) > 20:
                print(f"        ... ({len(users) - 20} more in loot/users.txt)")

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
            print(f"        {label} ({count})  → loot/{fname}  [hashcat -m {mode}]")
        if laps_count:
            print(f"        LAPS       ({laps_count})  → loot/creds_found.txt")

    # SMB file tree
    smb_root = ws.loot_dir / "creds_smb"
    if smb_root.exists():
        smb_files = list(smb_root.rglob("*"))
        file_count = sum(1 for f in smb_files if f.is_file())
        if file_count:
            print(f"\n  SMB Files ({file_count}):")
            print(f"        loot/creds_smb/")
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
                print(f"        {cl}")

    print()


def _save_valid_cred(ws: Workspace, line: str, password: str):
    m = re.search(r"\\(\S+)", line)
    username = m.group(1) if m else "unknown"
    with open(ws.loot_dir / "valid_creds.txt", "a") as f:
        f.write(f"{username}:{password}\n")


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
