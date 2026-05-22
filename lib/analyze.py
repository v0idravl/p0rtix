import os
from datetime import date

from lib.workspace import Workspace


def analyze_findings(
    ws: Workspace,
    ip: str,
    domain: str | None,
    model: str = "claude-sonnet-4-6",
) -> None:
    """Send findings.md + loot to Claude and stream back pentest analysis."""
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
        print("[!] findings.md not found — skipping AI analysis")
        return

    findings_content = ws.findings_path.read_text()

    loot_parts: list[str] = []
    users_path = ws.loot_dir / "users.txt"
    creds_path = ws.loot_dir / "creds_found.txt"
    if users_path.exists():
        users = users_path.read_text().strip()
        if users:
            loot_parts.append(f"Discovered users:\n{users}")
    if creds_path.exists():
        creds = creds_path.read_text().strip()
        if creds:
            loot_parts.append(f"Discovered credentials:\n{creds}")
    loot_section = "\n\n".join(loot_parts) if loot_parts else "None"

    domain_str = domain or "N/A"
    today = date.today().isoformat()

    prompt = f"""You are an expert penetration tester reviewing automated reconnaissance output from a stealthy, coverage-focused scan.

Do not reference whether this target may be a known machine, training platform, retired box, or published writeup. Treat it as an unknown target and analyse only from the technical evidence provided.

Analyse the findings below and respond with exactly these three sections:

## Executive Summary
2–3 sentences describing the target's attack surface and overall posture.

## Standout Findings
Bullet-point every significant item: exposed credentials, dangerous service versions, known CVEs, misconfigurations, unusual open ports, anything that immediately suggests a foothold or lateral-movement path.

## Recommended Attack Chain
An ordered list of concrete next steps from highest-impact/highest-likelihood to lowest. Include the specific tool or technique for each step (e.g. "Run `evil-winrm -i {ip} -u admin -p Password1`").

---
**Target IP:** {ip}
**Domain:** {domain_str}
**Scan date:** {today}

--- FINDINGS ---
{findings_content}

--- LOOT ---
{loot_section}"""

    client = anthropic.Anthropic(api_key=api_key)
    analysis_path = ws.machine_dir / "analysis.md"

    print(f"\n[*] Sending findings to Claude ({model}) for analysis...")
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
    header = f"# AI Analysis — {ip}\n\n*Model: {model} | Date: {today}*\n\n"
    analysis_path.write_text(header + full_analysis + "\n")
    print(f"[+] Analysis saved → {analysis_path}")
