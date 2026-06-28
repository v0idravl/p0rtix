"""Engine coverage for the broadened recon surface: web.enum + service.enum.

These wrap the existing lib/web.py and lib/services.py dispatchers as port-fanned
engine actions so the MCP/console can reach all recon, not just AD. The external
dispatchers are monkeypatched — no tools run — so we cover fan-out, gating, the
AD-port skip, and that dispatch reaches the right service."""
from lib import services, web
from lib.engine.action import Tier
from lib.engine.actions_builtin import build_registry
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler
from lib.models import Discovery, Service


class _FakeRunner:
    def __init__(self, ws):
        self.ws = ws
        self.fresh = False


def _svc(port, name, *, is_web=False, scheme="", proto="tcp"):
    return Service(port=port, proto=proto, name=name, version="", is_web=is_web, scheme=scheme)


def _wire(tmp_path):
    fs = FactStore("10.10.10.10", None, "svcweb", str(tmp_path))
    posture = Posture(dial=0)
    posture.raise_to(Tier.GREEN)
    reg = build_registry()
    sched = Scheduler(reg, fs, posture, ip="10.10.10.10",
                      runner=_FakeRunner(fs), tools={"curl", "nmap", "nxc"})
    return fs, posture, reg, sched


def test_web_enum_fans_out_per_web_service(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(
        web, "enumerate_web",
        lambda ip, svc, *a, **k: seen.append(svc.port) or
        [Discovery("ssl_san", "dc.htb", svc.port, svc.scheme, "san")])
    fs, posture, reg, sched = _wire(tmp_path)
    fs.add_services([_svc(80, "http", is_web=True, scheme="http"),
                     _svc(443, "https", is_web=True, scheme="https"),
                     _svc(22, "ssh")])

    n = sched.run_action("web.enum")
    assert n == 2 and sorted(seen) == [80, 443]
    # discovered hostname from the web pipeline lands in the fact store
    assert "dc.htb" in fs.snapshot()["hostnames"]


def test_whatweb_tech_parsing_is_whitelisted():
    clean = ("http://10/ [200 OK] Country[RESERVED][ZZ], "
             "HTTPServer[HttpFileServer 2.3], JQuery[1.4.4], "
             "Cookies[HFS_SID], IP[10.10.10.8]")
    techs = web._whatweb_tech(clean)
    assert "HTTPServer HttpFileServer 2.3" in techs
    assert "JQuery 1.4.4" in techs
    # cosmetic plugins (Country, Cookies, IP) are not recorded as tech
    assert not any(t.startswith(("Country", "Cookies", "IP")) for t in techs)


def test_record_web_tech_emits_into_factstore(tmp_path):
    fs, *_ = _wire(tmp_path)
    web._record_web_tech(_FakeRunner(fs), 80, ["HFS 2.3", "", "JQuery 1.4.4"])
    techs = {(x["port"], x["tech"]) for x in fs.snapshot()["web_tech"]}
    assert (80, "HFS 2.3") in techs and (80, "JQuery 1.4.4") in techs


def test_record_web_tech_noop_without_factstore():
    # legacy/headless path: a plain object with no add_web_tech must not raise
    class _Bare:
        ws = object()
    web._record_web_tech(_Bare(), 80, ["whatever"])   # no exception


def test_service_enum_covers_non_ad_and_skips_ad_ports(tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(services, "enumerate_service",
                        lambda ip, svc, *a, **k: seen.append(svc.port) or [])
    fs, posture, reg, sched = _wire(tmp_path)
    fs.add_services([
        _svc(1433, "ms-sql"),      # db → enumerated
        _svc(53, "domain"),        # dns → enumerated
        _svc(161, "snmp", proto="udp"),  # snmp → enumerated
        _svc(445, "microsoft-ds"), # AD → skipped (smb.* branch owns it)
        _svc(389, "ldap"),         # AD → skipped (ldap.* branch owns it)
        _svc(80, "http", is_web=True, scheme="http"),  # web → not a service.enum instance
    ])

    n = sched.run_action("service.enum")
    assert n == 3
    assert sorted(seen) == [53, 161, 1433]
    assert 445 not in seen and 389 not in seen and 80 not in seen


def test_service_enum_skips_unknown_service(tmp_path):
    fs, posture, reg, sched = _wire(tmp_path)
    fs.add_services([_svc(12345, "unknown-thing")])
    # no handler for the port/name → no instance, gate closed
    assert reg.get("service.enum").instances(fs) == []


def test_web_and_service_dormant_until_versiondetect(tmp_path):
    fs, posture, reg, sched = _wire(tmp_path)
    # ports open but not yet version-detected → no Service objects → dormant
    fs.add_open_port("tcp", 80)
    assert not reg.get("web.enum").is_available(fs)
    assert not reg.get("service.enum").is_available(fs)


# ── web_tech backfill (Validation delta) ────────────────────────────────────────
# When add_web_tech fires for a port with no service entry (or an is_web=False
# entry), the fact store must backfill a web service so web.enum is dispatched.


def test_add_web_tech_creates_stub_service_when_no_entry(tmp_path):
    """add_web_tech on a port with no service entry creates a minimal is_web=True
    stub so web.enum is available for that port (Validation pattern: whatweb
    detected Apache 2.4.48 on port 80 but version_detect produced no entry)."""
    fs, posture, reg, sched = _wire(tmp_path)
    # No services registered for port 80 yet
    assert fs.get_services() == []
    fs.add_web_tech(80, "Apache 2.4.48")
    svcs = fs.get_services()
    assert len(svcs) == 1
    s = svcs[0]
    assert s.port == 80 and s.proto == "tcp" and s.is_web is True
    assert s.scheme == "http"
    # Port must also be in open_ports so the port fact is consistent
    assert ("tcp", 80) in fs._open_ports


def test_add_web_tech_backfills_https_scheme_for_known_https_ports(tmp_path):
    """Port 443 gets scheme='https' when backfilled."""
    fs, *_ = _wire(tmp_path)
    fs.add_web_tech(443, "nginx 1.18")
    svcs = [s for s in fs.get_services() if s.port == 443]
    assert svcs and svcs[0].scheme == "https"


def test_add_web_tech_promotes_existing_non_web_service(tmp_path):
    """add_web_tech on a port whose existing service has is_web=False promotes it
    to is_web=True and assigns a scheme — covers a mis-classified service record."""
    fs, posture, reg, sched = _wire(tmp_path)
    fs.add_services([_svc(80, "http", is_web=False, scheme="")])
    assert not any(s.is_web for s in fs.get_services())
    fs.add_web_tech(80, "Apache 2.4.48")
    svcs = [s for s in fs.get_services() if s.port == 80]
    assert len(svcs) == 1 and svcs[0].is_web is True and svcs[0].scheme == "http"


def test_web_enum_available_after_web_tech_backfill(tmp_path, monkeypatch):
    """web.enum must become available for the backfilled port after add_web_tech."""
    seen = []
    monkeypatch.setattr(
        web, "enumerate_web",
        lambda ip, svc, *a, **k: seen.append(svc.port) or [],
    )
    fs, posture, reg, sched = _wire(tmp_path)
    # Simulate: version_detect produced no entry for port 80 (or a non-web entry),
    # but whatweb ran (e.g. piggybacking on port 8080 web.enum) and recorded tech.
    fs.add_web_tech(80, "Apache 2.4.48")
    assert reg.get("web.enum").is_available(fs)
    instances = reg.get("web.enum").instances(fs)
    assert any(i["port"] == 80 for i in instances)
    # Running web.enum now dispatches for port 80
    sched.run_action("web.enum")
    assert 80 in seen


def test_add_web_tech_no_double_backfill_when_already_web(tmp_path):
    """If the port already has is_web=True, add_web_tech does not emit a spurious
    service event and does not alter the existing entry."""
    fs, *_ = _wire(tmp_path)
    fs.add_services([_svc(80, "http", is_web=True, scheme="http")])
    events = []
    fs.subscribe(lambda ev: events.append(ev.kind) if ev.kind == "service" else None)
    fs.add_web_tech(80, "Apache 2.4.48")
    # No extra service event for an already-web service
    assert "service" not in events
    # Still only one service entry
    assert len([s for s in fs.get_services() if s.port == 80]) == 1
