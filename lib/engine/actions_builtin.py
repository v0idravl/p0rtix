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


def build_registry() -> ActionRegistry:
    reg = ActionRegistry()

    reg.register(Action(
        "recon.parse_prior", Tier.PASSIVE, _h_parse_prior,
        footprint=Footprint(summary="reads saved nmap XML (local only)"),
        gate=lambda f: any(f.machine_dir.joinpath("raw").glob("*_services.xml")),
    ))

    reg.register(Action(
        "discovery.tcp_ports", Tier.GREEN, _h_tcp_ports,
        footprint=Footprint(
            summary="full TCP SYN sweep",
            network="SYN sweep — firewall connection logs / IDS port-scan signature",
        ),
        deps=("nmap",),
    ))
    reg.register(Action(
        "discovery.udp_top100", Tier.GREEN, _h_udp_ports,
        footprint=Footprint(summary="top-100 UDP sweep",
                            network="UDP probes — firewall/IDS"),
        deps=("nmap",),
    ))
    reg.register(Action(
        "svc.version_detect", Tier.GREEN, _h_version_detect,
        footprint=Footprint(summary="per-port -sV banner grab",
                            network="extra connection + banner grab per port"),
        gate=lambda f: bool(_open_tcp_ports(f)),
        instances=_open_tcp_ports,
        requires=(Requirement("open_tcp", "an open TCP port"),),
        deps=("nmap",),
    ))

    reg.register(Action(
        "smb.anon_enum", Tier.GREEN, _h_smb_anon,
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
        footprint=Footprint(summary="anonymous LDAP bind + directory reads"),
        gate=lambda f: _ldap_port(f) is not None,
        requires=(Requirement("ldap_port", "LDAP (tcp/389|636|3268|3269) open"),),
        deps=("ldapsearch",),
    ))

    return reg
