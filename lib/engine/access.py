"""
Operator access — non-interactive command execution only.

Doctrine: p0rtix is recon, not C2. It does **not** implant, task, persist, or hand
the terminal off to an interactive shell. The furthest it goes is *testing* a
credential (see `creds.test`) and running **one** command non-interactively to
capture its stdout. Anything beyond that — interactive shells, lateral movement,
post-exploitation — is the exploitation agent's job (metasploitmcp), fed by
`export_handoff`.

`exec_command()` is pure (chooses the invocation, no I/O) so it stays
seam-mockable; the handler in `actions_builtin.py` runs it through the `Runner`.
"""
from __future__ import annotations


def _prefer_user(pairs):
    """Pick a real user account over a machine account ($)."""
    for u, p in pairs:
        if not u.endswith("$"):
            return u, p
    return pairs[0]


def exec_command(facts, ip: str, command: str) -> list[str] | None:
    """Choose the best non-interactive one-shot invocation for the access we have,
    or None if no credential/service combination can run a command.

    Preference mirrors the access we trust most: an admin credential over SMB
    (cmd exec via nxc), else a valid credential over WinRM, else SSH. The command
    is captured (stdout) — there is no interactive session and no tty handoff."""
    snap = facts.snapshot()
    open_tcp = {port for proto, port in snap["open_ports"] if proto == "tcp"}
    domain = snap["domain"] or ""
    admin = snap["admin_pairs"]
    valid = snap["valid_creds"]

    def _dom(svc):
        return ["-d", domain] if (domain and svc != "ssh") else []

    if 445 in open_tcp and admin:
        user, pw = _prefer_user(admin)
        return ["nxc", "smb", ip, "-u", user, "-p", pw, *_dom("smb"), "-x", command]

    if (5985 in open_tcp or 5986 in open_tcp) and valid:
        user, pw = _prefer_user(valid)
        cmd = ["nxc", "winrm", ip, "-u", user, "-p", pw, *_dom("winrm"), "-x", command]
        if 5986 in open_tcp and 5985 not in open_tcp:
            cmd.append("--ssl")                    # WinRM over HTTPS (5986)
        return cmd

    if 22 in open_tcp and valid:
        user, pw = _prefer_user(valid)
        # non-interactive: pass the command as the trailing ssh argument
        return ["sshpass", "-p", pw, "ssh", "-o", "StrictHostKeyChecking=no",
                f"{user}@{ip}", command]

    return None
