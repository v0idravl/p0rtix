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

Rules:
- Do not allude to or reference whether this target resembles any specific known environment, named machine, or published writeup. Draw conclusions only from the scan data below.
- Every recommendation in the Attack Chain must be immediately actionable using only the information present in the findings. Do not suggest steps that require credentials, usernames, hashes, or other artifacts that are not explicitly present. If a technique requires something not yet discovered, omit it entirely — do not frame it as conditional ("if you find X, then...").

Analyse the findings below and respond with exactly these three sections:

## Executive Summary
2–3 sentences describing the target's attack surface and overall posture based strictly on what was found.

## Standout Findings
Bullet-point every significant item visible in the scan data: exposed credentials, dangerous service versions, known CVEs applicable to identified versions, misconfigurations, unusual open ports, anything that immediately suggests a foothold or lateral-movement path.

## Recommended Attack Chain
Ordered list of next steps that can be executed right now with the access and information above. Each step must cite the specific evidence that makes it viable (e.g. "SMB null session confirmed → enumerate shares with..."). Omit any step whose prerequisites are not in the findings.

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
