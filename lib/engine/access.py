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

import os
import shlex
import subprocess


def in_tmux() -> bool:
    """True when p0rtix is running inside a tmux session — then a shell can open
    as a new tmux window (the TUI keeps running, detach/switch/close with tmux)
    instead of suspending the whole app."""
    return bool(os.environ.get("TMUX"))


def _tmux_new_window(argv=None, *, name=None, cwd=None) -> bool:
    """Open a new tmux window running `argv` (or a default shell), without leaving
    the current window. Returns True on success."""
    cmd = ["tmux", "new-window"]
    if name:
        cmd += ["-n", name]
    if cwd:
        cmd += ["-c", str(cwd)]
    if argv:
        cmd.append(shlex.join(argv))
    try:
        return subprocess.call(cmd) == 0
    except FileNotFoundError:
        return False


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
        return ["evil-winrm", "-i", ip, "-u", user, "-p", pw]

    if 22 in open_tcp and valid:
        user, pw = _prefer_user(valid)
        # non-interactive password → sshpass; operator can swap for a key
        return ["sshpass", "-p", pw, "ssh", "-o", "StrictHostKeyChecking=no",
                f"{user}@{ip}"]

    return None


def local_shell(cwd) -> int:
    """Drop the operator into a local `$SHELL` rooted at the workspace dir — for a
    quick manual command without leaving the console or hunting flags/passwords.

    Inside tmux this opens a new window (non-blocking; the console keeps running);
    otherwise it blocks in a child shell until they exit."""
    if in_tmux() and _tmux_new_window(name="p0rtix-cwd", cwd=cwd):
        return 0
    sh = os.environ.get("SHELL", "/bin/bash")
    try:
        return subprocess.call([sh], cwd=str(cwd))
    except FileNotFoundError:
        return subprocess.call(["/bin/sh"], cwd=str(cwd))
    except KeyboardInterrupt:
        return 130


def launch_shell(cmd: list[str]) -> int:
    """Spawn the interactive session. Inside tmux it opens as a new window (the
    console keeps running — detach/switch/close with tmux); otherwise it inherits
    the terminal and blocks (the TUI wraps that case in App.suspend()). The single
    spawn seam — tests monkeypatch it. Returns the child exit code (0 for tmux)."""
    if in_tmux() and _tmux_new_window(cmd, name="p0rtix-shell"):
        return 0
    try:
        return subprocess.call(cmd)
    except FileNotFoundError:
        print(f"[!] {cmd[0]} not found")
        return 127
    except KeyboardInterrupt:
        return 130
