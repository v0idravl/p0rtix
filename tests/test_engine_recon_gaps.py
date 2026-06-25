"""Recon-completeness actions: smb.signing, ad.coerce_surface, ad.adcs_enum,
mssql.enum. The external tools are faked via a canned-output runner — we cover
parsing, the fact/handoff signal, gating, and tier."""
from lib.engine.action import Tier
from lib.engine.actions_builtin import build_registry
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler


class _FakeRunner:
    def __init__(self, ws, out=""):
        self.ws = ws
        self.fresh = False
        self.out = out
        self.cmds = []

    def run(self, cmd, label, timeout=None):
        self.cmds.append(cmd)
        return self.out


def _wire(tmp_path, level=Tier.YELLOW, out="", tools=None, domain=None):
    fs = FactStore("10.10.10.10", domain, "gaps", str(tmp_path))
    if domain:
        fs.set_discovered_domain(domain)
    posture = Posture(dial=0)
    posture.raise_to(level)
    reg = build_registry()
    runner = _FakeRunner(fs, out)
    rendered: dict[str, str] = {}
    sched = Scheduler(reg, fs, posture, ip="10.10.10.10", runner=runner,
                      tools=tools or {"nxc", "impacket-rpcdump", "certipy-ad"},
                      on_output=lambda name, summ, md: rendered.update({name: md}))
    sched.rendered = rendered
    return fs, posture, reg, sched, runner


# ── smb.signing ───────────────────────────────────────────────────────────────
def test_smb_signing_flags_relay_target(tmp_path):
    out = "SMB  10.10.10.10  445  DC01  [*] Windows 10 (name:DC01) (signing:False) (SMBv1:False)"
    fs, posture, reg, sched, runner = _wire(tmp_path, Tier.GREEN, out=out)
    fs.add_open_port("tcp", 445)
    sched.run_action("smb.signing")
    assert fs.snapshot()["smb_signing_required"] is False


def test_smb_signing_required_is_not_a_relay_target(tmp_path):
    out = "SMB  10.10.10.10  445  DC01  [*] (signing:True) (SMBv1:False)"
    fs, posture, reg, sched, runner = _wire(tmp_path, Tier.GREEN, out=out)
    fs.add_open_port("tcp", 445)
    sched.run_action("smb.signing")
    assert fs.snapshot()["smb_signing_required"] is True


def test_smb_signing_is_green_and_gated_on_445(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path, Tier.GREEN)
    a = reg.get("smb.signing")
    assert a.tier is Tier.GREEN
    assert not a.is_available(fs)            # no 445 yet
    fs.add_open_port("tcp", 445)
    assert a.is_available(fs)


# ── ad.coerce_surface ─────────────────────────────────────────────────────────
def test_coerce_surface_detects_printerbug_and_petitpotam(tmp_path):
    out = ("Protocol: [MS-RPRN]: Print System Remote Protocol\n"
           "12345678-1234-abcd-ef00-0123456789ab v1.0\n"
           "c681d488-d850-11d0-8c52-00c04fd90f7e v1.0 MS-EFSR\n")
    fs, posture, reg, sched, runner = _wire(tmp_path, Tier.GREEN, out=out)
    fs.add_open_port("tcp", 135)
    sched.run_action("ad.coerce_surface")
    md = sched.rendered["ad.coerce_surface"]
    assert "PrinterBug" in md and "PetitPotam" in md


def test_coerce_surface_gated_on_135(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path, Tier.GREEN)
    assert not reg.get("ad.coerce_surface").is_available(fs)
    fs.add_open_port("tcp", 135)
    assert reg.get("ad.coerce_surface").is_available(fs)


# ── ad.adcs_enum ──────────────────────────────────────────────────────────────
def test_adcs_enum_needs_domain_and_cred(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path, Tier.YELLOW)  # no domain/cred
    a = reg.get("ad.adcs_enum")
    assert a.tier is Tier.YELLOW
    assert not a.is_available(fs)
    fs.set_discovered_domain("corp.local")
    fs.add_valid_cred("svc", "pw", "SMB")
    assert a.is_available(fs)


# ── mssql.enum ────────────────────────────────────────────────────────────────
def test_mssql_enum_gated_on_1433_and_cred(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path, Tier.YELLOW)
    a = reg.get("mssql.enum")
    assert a.tier is Tier.YELLOW and a.group == "service"
    fs.add_open_port("tcp", 1433)
    assert not a.is_available(fs)            # cred still missing
    fs.add_valid_cred("sa", "pw", "MSSQL")
    assert a.is_available(fs)


def test_mssql_enum_runs_db_and_linked_queries(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path, Tier.YELLOW, domain="corp.local")
    fs.add_open_port("tcp", 1433)
    fs.add_valid_cred("sa", "pw", "MSSQL")
    sched.run_action("mssql.enum")
    qs = [c[c.index("-q") + 1] for c in runner.cmds if "-q" in c]
    assert any("sys.databases" in q for q in qs)
    assert any("sp_linkedservers" in q for q in qs)
