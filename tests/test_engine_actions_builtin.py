"""Mocked tests for the green action wrappers. The underlying nmap / service
functions are monkeypatched, so no tools run — we assert the wrappers gate
correctly and push the expected facts through the scheduler."""
from lib import nmap, services
from lib.engine.action import Tier
from lib.engine.actions_builtin import build_registry
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.registry import instance_key
from lib.engine.scheduler import Scheduler
from lib.models import Service


class _FakeRunner:
    def __init__(self, ws, output=""):
        self.ws = ws
        self.output = output           # canned stdout for run()

    def run(self, cmd, label, timeout=None):
        return self.output


_ALL_TOOLS = {"nmap", "nxc", "ldapsearch", "impacket-lookupsid",
              "impacket-GetNPUsers", "hashcat"}


def _setup(tmp_path, level, *, output="", tools=None):
    fs = FactStore("192.0.2.10", None, "ab-test", str(tmp_path))
    posture = Posture()
    posture.raise_to(level)
    reg = build_registry()
    sched = Scheduler(
        reg, fs, posture, ip="192.0.2.10", runner=_FakeRunner(fs, output),
        tools=tools if tools is not None else {"nmap", "nxc", "ldapsearch",
                                               "impacket-lookupsid"},
    )
    return fs, posture, reg, sched


def test_registry_has_phase1_actions(tmp_path):
    reg = build_registry()
    names = {a.name for a in reg.all()}
    assert {"discovery.tcp_ports", "svc.version_detect",
            "smb.anon_enum", "ldap.anon_bind"} <= names


def test_discovery_adds_open_ports_as_facts(tmp_path, monkeypatch):
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws: [22, 445])
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN)

    sched.run_action("discovery.tcp_ports")
    assert fs.has("tcp/22") and fs.has("tcp/445")


def test_version_detect_is_per_port_and_gated(tmp_path, monkeypatch):
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws: [22, 445])
    monkeypatch.setattr(
        nmap, "version_detect",
        lambda ip, ports, r, ws: [Service(ports[0], "tcp", "svc", "1.0", False, "")],
    )
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN)

    # No ports yet → version_detect is dormant.
    assert "svc.version_detect" in {a.name for a, _ in reg.dormant(fs)}

    sched.run_action("discovery.tcp_ports")
    avail = [(a, args) for a, args in reg.available(fs, posture, sched.tried)
             if a.name == "svc.version_detect"]
    assert sorted(args["port"] for _, args in avail) == [22, 445]


def test_smb_anon_gated_on_445_and_pushes_facts(tmp_path, monkeypatch):
    from lib.engine.action import Tier

    def fake_null(ip, port, runner, buf, available):
        runner.ws.add_user("alice", authoritative=True)
        runner.ws.set_discovered_domain("test.htb")

    monkeypatch.setattr(services, "_smb_run_null_session", fake_null)
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN)

    # gated out before 445 is known
    assert "smb.anon_enum" not in {a.name for a, _ in reg.available(fs, posture, sched.tried)}
    fs.add_open_port("tcp", 445)
    assert "smb.anon_enum" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}

    sched.run_action("smb.anon_enum")
    assert "alice" in fs.snapshot()["users"]
    assert fs.discovered_domain == "test.htb"


def test_run_all_cascade_discovery_to_enumeration(tmp_path, monkeypatch):
    from lib.engine.action import Tier
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws: [445])
    monkeypatch.setattr(nmap, "version_detect",
                        lambda ip, ports, r, ws: [])

    def fake_null(ip, port, runner, buf, available):
        runner.ws.add_user("bob", authoritative=True)

    monkeypatch.setattr(services, "_smb_run_null_session", fake_null)
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN)

    sched.run_all_at_or_below()
    names = {n for n, _ in sched.completed}
    # discovery ran, then 445 unlocked both version-detect (port 445) and smb
    assert "discovery.tcp_ports" in names
    assert instance_key("svc.version_detect", {"port": 445}) in sched.tried
    assert "smb.anon_enum" in names
    assert "bob" in fs.snapshot()["users"]


def test_smb_supersedes_enum4linux(tmp_path):
    reg = build_registry()
    smb = reg.get("smb.anon_enum")
    assert "smb.enum4linux" in smb.supersedes


# ── AS-REP roast + crack (the Forest foothold chain) ──────────────────────────
_FAKE_ASREP = (
    "[*] Getting TGT for svc-alfresco\n"
    "$krb5asrep$23$svc-alfresco@HTB.LOCAL:abc123$def456\n"
    "[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set\n"
)


def test_asrep_roast_gated_on_domain_and_users(tmp_path):
    from lib.engine.action import Tier
    fs, posture, reg, sched = _setup(tmp_path, Tier.YELLOW, tools=_ALL_TOOLS)

    # dormant until BOTH a domain and a user list are known
    assert "kerberos.asrep_roast" in {a.name for a, _ in reg.dormant(fs)}
    fs.set_discovered_domain("htb.local")
    assert "kerberos.asrep_roast" in {a.name for a, _ in reg.dormant(fs)}
    fs.add_user("svc-alfresco", authoritative=True)
    assert "kerberos.asrep_roast" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}


def test_asrep_roast_captures_hash_and_unlocks_crack(tmp_path):
    from lib.engine.action import Tier
    fs, posture, reg, sched = _setup(tmp_path, Tier.YELLOW,
                                     output=_FAKE_ASREP, tools=_ALL_TOOLS)
    fs.set_discovered_domain("htb.local")
    fs.add_user("svc-alfresco", authoritative=True)

    # crack is dormant with no hash yet
    assert not fs.has("hash")
    sched.run_action("kerberos.asrep_roast")

    assert fs.has("hash") and fs.has("hash:asrep")
    saved = (fs.loot_dir / "asrep.hash").read_text()
    assert "$krb5asrep$" in saved
    # PASSIVE crack is now available (offline, runs at/below any posture)
    assert "crack.hashes" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}


def test_creds_spray_gated_on_candidate_and_smb(tmp_path):
    from lib.engine.action import Tier
    fs, posture, reg, sched = _setup(tmp_path, Tier.YELLOW, tools=_ALL_TOOLS)

    assert "creds.spray" in {a.name for a, _ in reg.dormant(fs)}
    fs.add_cred("s3rvice")                       # candidate, still no SMB port
    assert "creds.spray" in {a.name for a, _ in reg.dormant(fs)}
    fs.add_open_port("tcp", 445)
    assert "creds.spray" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}


def test_creds_spray_promotes_candidate_to_valid(tmp_path, monkeypatch):
    from lib.engine.action import Tier
    import p0rtix

    def fake_reuse(ip, runner, findings, ws, services, available):
        # simulate a confirmed hit from the spray
        ws.add_valid_cred("svc-alfresco", "s3rvice", "SMB")

    monkeypatch.setattr(p0rtix, "_run_cred_reuse", fake_reuse)
    fs, posture, reg, sched = _setup(tmp_path, Tier.YELLOW, tools=_ALL_TOOLS)
    fs.add_cred("s3rvice")
    fs.add_open_port("tcp", 445)

    sched.run_action("creds.spray")
    assert fs.has("valid_cred")
    assert ("svc-alfresco", "s3rvice") in {(u, p) for u, p in fs._known_valid}


def test_ad_core_gated_on_valid_cred_and_domain(tmp_path):
    from lib.engine.action import Tier
    fs, posture, reg, sched = _setup(tmp_path, Tier.YELLOW, tools=_ALL_TOOLS)

    assert "ad.authenticated_core" in {a.name for a, _ in reg.dormant(fs)}
    fs.set_discovered_domain("htb.local")
    fs.add_valid_cred("svc-alfresco", "s3rvice", "SMB")
    assert "ad.authenticated_core" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}


def test_pick_enum_cred_prefers_user_over_machine(tmp_path):
    from lib.engine.actions_builtin import _pick_enum_cred
    fs = FactStore("10.0.0.1", None, "pick", str(tmp_path))
    fs.add_valid_cred("FOREST$", "machinepw", "SMB")
    fs.add_valid_cred("svc-alfresco", "s3rvice", "SMB")
    assert _pick_enum_cred(fs) == ("svc-alfresco", "s3rvice")


def test_asrep_roast_no_roastable_marks_kerberos_exhausted(tmp_path):
    from lib.engine.action import Tier
    from lib.engine.facts import ProtoStatus
    fs, posture, reg, sched = _setup(tmp_path, Tier.YELLOW,
                                     output="[-] no preauth accounts\n", tools=_ALL_TOOLS)
    fs.set_discovered_domain("htb.local")
    fs.add_user("andy", authoritative=True)

    sched.run_action("kerberos.asrep_roast")
    assert not fs.has("hash")
    assert fs.proto_status("kerberos") is ProtoStatus.EXHAUSTED
