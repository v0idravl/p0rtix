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
