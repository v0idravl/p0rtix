import os
import re
from datetime import date

from lib.workspace import Workspace


def analyze_findings(
    ws: Workspace,
    ip: str,
    domain: str | None,
    model: str = "claude-sonnet-4-6",
    mode: str = "scan",
) -> None:
    """Send findings + loot to Claude and stream back pentest analysis."""
    try:
        import anthropic
    except ImportError:
        print("[!] anthropic SDK not installed — run: pip install anthropic")
        return

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("[!] ANTHROPIC_API_KEY not set — skipping AI analysis")
        return

    if not ws.findings_path.exists():
        print(f"[!] {ws.findings_path.name} not found — skipping AI analysis")
        return

    findings_content = ws.findings_path.read_text()
    domain_str = domain or "N/A"
    today = date.today().isoformat()

    # Derive output path from the findings filename (creds_findings.md → creds_analysis.md)
    analysis_path = ws.findings_path.parent / ws.findings_path.name.replace("findings", "analysis")

    if mode == "creds":
        loot_parts = _build_creds_loot(ws)
        scan_findings_path = ws.machine_dir / "findings.md"
        scan_context = scan_findings_path.read_text() if scan_findings_path.exists() else ""
        prompt = _creds_prompt(ip, domain_str, today, findings_content, loot_parts, scan_context)
    else:
        loot_parts = _build_scan_loot(ws)
        prompt = _scan_prompt(ip, domain_str, today, findings_content, loot_parts)

    client = anthropic.Anthropic(api_key=api_key)

    print(f"\n[*] Sending {ws.findings_path.name} to Claude ({model}) for analysis...")
    print("=" * 60)

    chunks: list[str] = []
    with client.messages.stream(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    ) as stream:
        for text in stream.text_stream:
            print(text, end="", flush=True)
            chunks.append(text)

    print("\n" + "=" * 60)

    full_analysis = "".join(chunks)
    header = f"# AI Analysis — {ip}\n\n*Model: {model} | Mode: {mode} | Date: {today}*\n\n"
    analysis_path.write_text(header + full_analysis + "\n")
    print(f"[+] Analysis saved → {analysis_path}")


def _redact_creds(content: str) -> str:
    """Replace password in 'user:password  [service]' and 'user:password' lines."""
    lines = []
    for line in content.splitlines():
        m = re.match(r'^([^:]+):(\S+)(.*)', line)
        if m:
            lines.append(f"{m.group(1)}:[REDACTED]{m.group(3)}")
        else:
            lines.append(line)
    return "\n".join(lines)


def _build_scan_loot(ws: Workspace) -> str:
    parts: list[str] = []
    for filename, label in (
        ("users.txt", "Discovered users"),
        ("creds_found.txt", "Discovered credentials"),
    ):
        p = ws.loot_dir / filename
        if p.exists():
            content = p.read_text().strip()
            if content:
                redacted = _redact_creds(content) if filename == "creds_found.txt" else content
                parts.append(f"{label}:\n{redacted}")
    return "\n\n".join(parts) if parts else "None"


def _build_creds_loot(ws: Workspace) -> str:
    parts: list[str] = []
    for filename, label in (
        ("valid_creds.txt", "Validated credentials"),
        ("users.txt", "Domain users"),
        ("kerberoast.hash", "Kerberoastable hashes (hashcat -m 13100)"),
        ("asrep.hash", "AS-REP hashes (hashcat -m 18200)"),
        ("ntlm.hash", "NTLM hashes (hashcat -m 1000 / pass-the-hash)"),
        ("creds_found.txt", "Additional credentials found"),
    ):
        p = ws.loot_dir / filename
        if p.exists():
            content = p.read_text().strip()
            if content:
                redacted = _redact_creds(content) if filename in ("valid_creds.txt", "creds_found.txt") else content
                parts.append(f"{label}:\n{redacted}")
    return "\n\n".join(parts) if parts else "None"


def _scan_prompt(ip: str, domain_str: str, today: str, findings: str, loot: str) -> str:
    return f"""You are an expert penetration tester reviewing automated reconnaissance output from a scope-aware authorized assessment scan.

Rules:
- Do not allude to or reference whether this target resembles any specific known environment, named machine, or published writeup. Draw conclusions only from the scan data below.
- Every recommendation in the Attack Chain must be immediately actionable using only the information present in the findings. Do not suggest steps that require credentials, usernames, hashes, or other artifacts that are not explicitly present. If a technique requires something not yet discovered, omit it entirely — do not frame it as conditional ("if you find X, then...").
- When exploit references appear in the "Exploit References" section, cite specific EDB IDs (e.g. EDB-XXXXX), GitHub PoC URLs if well-known, or Metasploit module paths rather than generic exploit category names.

Analyse the findings below and respond with exactly these four sections:

## Executive Summary
2–3 sentences describing the target's attack surface and overall posture based strictly on what was found.

## Standout Findings
Bullet-point every significant item visible in the scan data: exposed credentials, dangerous service versions, known CVEs applicable to identified versions, misconfigurations, unusual open ports, anything that immediately suggests a foothold or lateral-movement path.

## Recommended Attack Chain
Ordered list of next steps that can be executed right now with the access and information above. Each step must cite the specific evidence that makes it viable (e.g. "SMB null session confirmed → enumerate shares with...") and where applicable reference the specific exploit (EDB ID, MSF module, or GitHub PoC). Omit any step whose prerequisites are not in the findings.

## Tool Improvement Suggestions
Review the raw output quality in this report — commands that failed, timed out, returned empty results, or had parser issues. Suggest specific, actionable improvements to the p0rtix automated tool: better arguments, smarter fallbacks, missing coverage, or additional tools that would help. Be concise and specific. Omit this section entirely if output quality is good with no obvious gaps.

---
**Target IP:** {ip}
**Domain:** {domain_str}
**Scan date:** {today}

--- FINDINGS ---
{findings}

--- LOOT ---
{loot}"""


def _creds_prompt(ip: str, domain_str: str, today: str, findings: str, loot: str, scan_context: str = "") -> str:
    scan_section = (
        f"\n--- PRIOR RECON FINDINGS (unauthenticated scan) ---\n{scan_context}\n"
        if scan_context else ""
    )
    return f"""You are an expert penetration tester reviewing credentialed Active Directory enumeration output from an automated tool.

Rules:
- Do not allude to or reference whether this target resembles any specific known environment, named machine, or published writeup. Draw conclusions only from the data below.
- Every recommendation must be immediately actionable using only the artifacts present in the findings (valid credentials, hashes, user lists, share names, ADCS templates, etc.). Do not suggest steps that require artifacts not present. If a technique requires something not yet found, omit it entirely.
- Be specific: cite exact usernames, share names, hash types, ESC numbers, and complete tool commands grounded in the evidence.
- Where exploit references appear, cite specific EDB IDs, GitHub PoC URLs, or Metasploit module paths rather than generic categories.

Analyse the findings below and respond with exactly these four sections:

## Executive Summary
2–3 sentences describing the current access level, what was enumerated with the provided credentials, and the overall position in the engagement.

## Standout Findings
Bullet every significant item: valid credentials and their access level (standard user vs admin vs Pwn3d!), Kerberoastable and AS-REP roastable accounts, NTLM hashes obtained, ADCS misconfigurations (ESC1–ESC8), accessible SMB shares and any notable files, BloodHound shortest-path attack paths if referenced, any existing domain-admin or local-admin access.

## Recommended Next Steps
Ordered list of the highest-value actions from the current position. Prioritise domain compromise and credential escalation paths. Each step must cite specific evidence (e.g. "Admin SMB (`Pwn3d!`) for `administrator` → lateral movement with `impacket-psexec {domain_str}/administrator:[REDACTED]@{ip}`"). Omit any step whose prerequisites are absent from the findings.

## Tool Improvement Suggestions
Review the raw output quality in this report — commands that failed, timed out, returned empty results, or had parser issues. Suggest specific, actionable improvements to the p0rtix automated tool: better arguments, smarter fallbacks, missing coverage, or additional tools that would help. Be concise and specific. Omit this section entirely if output quality is good with no obvious gaps.

---
**Target IP:** {ip}
**Domain:** {domain_str}
**Date:** {today}

--- CREDENTIALED FINDINGS ---
{findings}
{scan_section}
--- LOOT ---
{loot}"""
