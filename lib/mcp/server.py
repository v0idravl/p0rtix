"""
p0rtix MCP server — a FastMCP stdio wrapper over `McpSession` / `SessionManager`.

The tool surface is deliberately small and generic: it mirrors the engine
(open a target, list/run actions, inspect state, set posture, populate facts,
export the handoff) rather than exposing one tool per recon technique. Every
current and future Action is therefore reachable through `list_actions` +
`run_action` with no new tool code.

The server registers *statically* — no target at launch — and the agent calls
`open_target(ip, domain?)` to begin (the same way it would `msf-up` then drive
metasploitmcp). One registered `p0rtix-mcp` serves box after box.

Each tool is `async` and bridges to the synchronous, subprocess-heavy engine via
`anyio.to_thread.run_sync`; `McpSession` holds a per-session lock so concurrent
tool calls serialise cleanly. The `mcp` SDK is an optional dependency (`[mcp]`
extra); this module is only imported by `--mode mcp` / the `p0rtix-mcp` entry
point, so the stdlib-only core is unaffected when the SDK is absent.
"""
from __future__ import annotations

import argparse
import sys
from types import SimpleNamespace

from lib.mcp.session import SessionManager

_NO_TARGET = {"ok": False, "error": "no target open — call open_target(ip, domain?) first"}


def build_server(manager: SessionManager):
    """Construct the FastMCP app with all tools bound to `manager`."""
    import anyio
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("p0rtix")

    async def _scall(method: str, *args):
        """Run a session method in a worker thread, guarding for an open target."""
        s = manager.current
        if s is None:
            return _NO_TARGET
        return await anyio.to_thread.run_sync(lambda: getattr(s, method)(*args))

    @server.tool()
    async def open_target(ip: str, domain: str | None = None,
                          name: str | None = None) -> dict:
        """Open (or resume) a recon session against a target and make it current.
        Call this first. `ip` is the target; `domain` is its AD/FQDN if known;
        `name` is an optional workspace label (defaults to the IP). Re-opening the
        same target resumes its state. Returns the initial engine state."""
        def _open():
            manager.open(ip, domain, name)
            return manager.current.get_state()
        return await anyio.to_thread.run_sync(_open)

    @server.tool()
    async def get_state() -> dict:
        """Return the authoritative engine state for the current target: discovered
        facts (open ports, versioned services, users, valid/admin credentials,
        hashes, hostnames, SMB-signing) plus scheduler progress."""
        return await _scall("get_state")

    @server.tool()
    async def list_actions(include_dormant: bool = True) -> list[dict] | dict:
        """List every recon action with its planning state. Each entry has: name,
        group, tier (passive/green/yellow/red noise), state (available/blocked/
        dormant/exhausted), footprint, deps, manual_only, instances, and a one-line
        `why`. Use this to plan the next step. Set include_dormant=False for only
        what is runnable now."""
        return await _scall("list_actions", include_dormant)

    @server.tool()
    async def run_action(name: str, port: int | None = None,
                         args: dict | None = None) -> dict:
        """Run one action by name (re-runs fresh if already done). `port` targets a
        single per-port instance. `args` carries free-text payloads (e.g.
        {"command": "whoami"} for access.exec, or {"breadth": "broad"}). Returns
        {ok, summary, facts_delta, findings_md}: `facts_delta` is the new facts
        learned (incl. versioned services), `findings_md` the rendered detail."""
        return await _scall("run_action", name, port, args)

    @server.tool()
    async def run_group(group: str) -> dict:
        """Run a whole branch of actions (e.g. group="smb" runs every available SMB
        sub-action), cascading as facts unlock more within the group."""
        return await _scall("run_group", group)

    @server.tool()
    async def run_all(noise_ceiling: str | None = None) -> dict:
        """Run everything available at/below the current noise ceiling, cascading on
        newly-learned facts until quiescent. Optionally pass noise_ceiling
        (green/yellow/red) to raise the ceiling first — the 'do a standard pass'
        sweep."""
        return await _scall("run_all", noise_ceiling)

    @server.tool()
    async def start_full_scan() -> dict:
        """Kick a full TCP (-p-) sweep in the BACKGROUND so recon keeps moving on
        the quick-scan ports while the slow sweep runs. Newly-found ports flow into
        the fact store automatically — poll background_status (or watch get_state's
        open_ports / background block). Safe to call once near the start of a box."""
        return await _scall("start_full_scan")

    @server.tool()
    async def background_status() -> dict:
        """Report the background full-TCP sweep: {running, new_ports, done/error}.
        New ports also surface in get_state's open_ports as they are found."""
        return await _scall("background_status")

    @server.tool()
    async def set_noise(level: str) -> dict:
        """Set the noise ceiling: passive (no packets), green (discovery + safe
        reads), yellow (writes auth events), red (locked unless armed). Actions
        only run when their tier is at/below this level. Quiet by default."""
        return await _scall("set_noise", level)

    @server.tool()
    async def arm_dangerous() -> dict:
        """Unlock RED-tier (destructive/exploit-grade) actions. Required before any
        red action runs. Use deliberately."""
        return await _scall("arm_dangerous")

    @server.tool()
    async def set_breadth(level: str) -> dict:
        """Set the concise→broad effort knob (orthogonal to the noise ladder):
        concise (fast, surgical), standard (a light pass), broad (leave no stone
        unturned — slow). Scales offline crack rule depth and web dir/vhost
        wordlists. Raise before crack.hashes / web.enum for maximum coverage."""
        return await _scall("set_breadth", level)

    @server.tool()
    async def add_fact(kind: str, value: str) -> dict:
        """Seed a fact by hand to unlock dependent actions. kind is one of:
        "user" (value=username), "creds" (value="user:pass"), "domain"
        (value=domain). e.g. add_fact("creds", "svc-admin:Summer2024")."""
        return await _scall("add_fact", kind, value)

    @server.tool()
    async def reload() -> dict:
        """Re-read the loot/*.txt files from disk into the fact store, picking up any
        external edits. Returns the count of new facts."""
        return await _scall("reload")

    @server.tool()
    async def recheck(proto: str | None = None) -> dict:
        """Re-arm a dormant branch. proto="users" re-arms user-list actions; any
        protocol name (e.g. "ldap") forgets that branch's status and re-arms its
        actions so they can run again."""
        return await _scall("recheck", proto)

    @server.tool()
    async def export_handoff() -> dict:
        """Export the structured recon inventory for the current target.

        Returns a hosts[] array containing the target's open ports, versioned
        services, valid/admin credentials, cred pairs, captured hashes, relay
        target flag, hostnames, and users. Also syncs facts into the dagar-state
        engagement store if one is open. Pure read — p0rtix recons and hands off;
        it does not exploit."""
        return await _scall("export_handoff")

    @server.tool()
    async def export_all_handoffs() -> dict:
        """Export merged recon inventory across ALL open sessions (multi-host).

        Returns a hosts[] array with one entry per open target, suitable for
        feeding a full-engagement picture into the C2/exploitation agent. Use
        export_handoff() for single-target work; this tool is for pivot/multi-host
        engagements where p0rtix has multiple open targets simultaneously."""
        def _all():
            return manager.export_all_handoffs()
        return await anyio.to_thread.run_sync(_all)

    return server


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="p0rtix-mcp",
        description="p0rtix recon engine as an MCP (stdio) server for an AI agent. "
                    "Registers statically; the agent calls open_target to begin.",
    )
    p.add_argument("ip", nargs="?", default=None,
                   help="Optional target to pre-open (else call open_target)")
    p.add_argument("--domain", "-d", default=None, help="AD domain (FQDN) for the pre-opened target")
    p.add_argument("--name", "-n", default=None, help="Workspace name (defaults to target)")
    p.add_argument("--workspace", "-w", default=".", help="Workspace root directory")
    p.add_argument("--level", type=int, default=0, metavar="0-9",
                   help="Startup automation dial (0=manual/quiet; the agent steers noise itself)")
    p.add_argument("--deep", action="store_true", help="Default to broad wordlists/web checks")
    p.add_argument("--users", default=None, metavar="FILE", help="Seed usernames from a file")
    p.add_argument("--install", action="store_true",
                   help="Allow installing missing tools (off by default — no prompts over stdio)")
    return p.parse_args(argv)


def _manager_from(ns) -> SessionManager:
    """Build a SessionManager from parsed args (no interactive install over stdio)."""
    from lib.deps import check_deps
    available = check_deps(install_missing=ns.install)
    args = SimpleNamespace(
        workspace=ns.workspace, deep=ns.deep, level=ns.level,
        users=ns.users, headless=True,
    )
    manager = SessionManager(args, available)
    if ns.ip:                         # optionally pre-open a target
        manager.open(ns.ip, ns.domain, ns.name)
    return manager


def main(argv: list[str] | None = None) -> None:
    ns = _parse_args(sys.argv[1:] if argv is None else argv)
    if not (0 <= ns.level <= 9):
        sys.exit("[!] --level must be between 0 and 9")
    manager = _manager_from(ns)
    build_server(manager).run()  # stdio transport (default)


if __name__ == "__main__":
    main()
