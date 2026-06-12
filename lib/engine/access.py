"""
Operator access — the opt-in interactive shell handoff.

Doctrine note: p0rtix is recon, not C2. It does **not** implant, task, or
persist. This module is the one deliberate, operator-armed exception: once a
working credential is confirmed it can *hand the terminal off* into a normal
interactive `evil-winrm` / `impacket-psexec` session. The shell is a stock tool
driven by the human; p0rtix only chooses the right invocation and steps aside.

Kept pure + seam-mockable: `shell_command()` decides what to launch (no I/O);
`launch_shell()` is the single spawn point a test or the TUI overrides.
"""
from __future__ import annotations

import subprocess


def _prefer_user(pairs):
    """Pick a real user account over a machine account ($)."""
    for u, p in pairs:
        if not u.endswith("$"):
            return u, p
    return pairs[0]


def shell_command(facts, ip: str) -> list[str] | None:
    """Choose the best interactive-shell invocation for the access we have, or
    None if no credential/service combination yields a shell.

    Preference: an admin credential over SMB → SYSTEM shell via psexec; otherwise
    a valid credential over WinRM → user shell via evil-winrm. A non-admin SMB-only
    credential gives no shell (returns None)."""
    snap = facts.snapshot()
    open_tcp = {port for proto, port in snap["open_ports"] if proto == "tcp"}
    domain = snap["domain"] or ""
    admin = snap["admin_pairs"]
    valid = snap["valid_creds"]

    if 445 in open_tcp and admin:
        user, pw = _prefer_user(admin)
        target = f"{domain}/{user}:{pw}@{ip}" if domain else f"{user}:{pw}@{ip}"
        return ["impacket-psexec", target]

    if 5985 in open_tcp and valid:
        user, pw = _prefer_user(valid)
        cmd = ["evil-winrm", "-i", ip, "-u", user, "-p", pw]
        return cmd

    return None


def launch_shell(cmd: list[str]) -> int:
    """Spawn the interactive session, inheriting the terminal, and block until the
    operator exits it. The single spawn seam — the TUI wraps this in App.suspend()
    and tests monkeypatch it. Returns the child exit code."""
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        print(f"[!] {cmd[0]} not found")
        return 127
    except KeyboardInterrupt:
        return 130
