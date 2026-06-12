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
              "impacket-GetNPUsers", "hashcat", "ldapdomaindump",
              "impacket-GetUserSPNs", "bloodhound-python", "bloodyAD"}


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
    assert {"discovery.tcp_ports", "svc.version_detect", "smb.users",
            "ldap.domain_info", "ldap.users", "ldap.groups",
            "ldap.delegation"} <= names


def test_discovery_adds_open_ports_as_facts(tmp_path, monkeypatch):
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws, exclude=None: [22, 445])
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN)

    sched.run_action("discovery.tcp_ports")
    assert fs.has("tcp/22") and fs.has("tcp/445")


def test_version_detect_is_per_port_and_gated(tmp_path, monkeypatch):
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws, exclude=None: [22, 445])
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


def test_smb_users_gated_on_445_and_pushes_facts(tmp_path, monkeypatch):
    from lib.engine.action import Tier

    def fake_users(ip, port, runner, buf, available):
        runner.ws.add_user("alice", authoritative=True)
        runner.ws.set_discovered_domain("test.htb")

    monkeypatch.setattr(services, "_smb_users", fake_users)
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN)

    # gated out before 445 is known
    assert "smb.users" not in {a.name for a, _ in reg.available(fs, posture, sched.tried)}
    fs.add_open_port("tcp", 445)
    assert "smb.users" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}

    sched.run_action("smb.users")
    assert "alice" in fs.snapshot()["users"]
    assert fs.discovered_domain == "test.htb"


def test_run_all_cascade_discovery_to_enumeration(tmp_path, monkeypatch):
    from lib.engine.action import Tier
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws, exclude=None: [445])
    monkeypatch.setattr(nmap, "version_detect",
                        lambda ip, ports, r, ws: [])
    # neutralise the other smb sub-actions; smb.users records the user
    for fn in ("_smb_shares", "_smb_spider_shares", "_smb_policy"):
        monkeypatch.setattr(services, fn, lambda *a, **k: None)
    monkeypatch.setattr(services, "_smb_users",
                        lambda ip, port, runner, buf, available: runner.ws.add_user("bob", authoritative=True))
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN)

    sched.run_all_at_or_below()
    names = {n for n, _ in sched.completed}
    # discovery ran, then 445 unlocked both version-detect (port 445) and smb
    assert "discovery.tcp_ports" in names
    assert instance_key("svc.version_detect", {"port": 445}) in sched.tried
    assert "smb.users" in names
    assert "bob" in fs.snapshot()["users"]


def test_smb_branch_decomposed_and_users_supersedes_enum4linux(tmp_path):
    reg = build_registry()
    names = {a.name for a in reg.all()}
    assert {"smb.users", "smb.shares", "smb.spider", "smb.policy"} <= names
    assert "smb.anon_enum" not in names
    assert "smb.enum4linux" in reg.get("smb.users").supersedes


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


_GRANULAR_AD = {"ldap.domaindump", "kerberos.kerberoast",
                "bloodhound.collect", "ad.writable_objects"}


def test_granular_ad_actions_gated_on_valid_cred_and_domain(tmp_path):
    from lib.engine.action import Tier
    fs, posture, reg, sched = _setup(tmp_path, Tier.YELLOW, tools=_ALL_TOOLS)

    # the monolith is gone; each AD step is its own action
    assert "ad.authenticated_core" not in {a.name for a in reg.all()}
    dormant = {a.name for a, _ in reg.dormant(fs)}
    assert _GRANULAR_AD <= dormant

    fs.set_discovered_domain("htb.local")
    fs.add_valid_cred("svc-alfresco", "s3rvice", "SMB")
    avail = {a.name for a, _ in reg.available(fs, posture, sched.tried)}
    assert _GRANULAR_AD <= avail


def test_creds_test_verifies_pair_without_spray(tmp_path):
    from lib.engine.action import Tier
    # nxc reports a WinRM hit for the exact pair
    out = "WINRM  10.0.0.1  5985  DC  [+] htb.local\\svc-alfresco:s3rvice (Pwn3d!)\n"
    fs, posture, reg, sched = _setup(tmp_path, Tier.YELLOW, output=out, tools=_ALL_TOOLS)

    # dormant until there's a pair to test
    assert "creds.test" in {a.name for a, _ in reg.dormant(fs)}
    fs.add_cred_pair("svc-alfresco", "s3rvice")
    fs.add_open_port("tcp", 445)
    fs.add_open_port("tcp", 5985)
    assert "creds.test" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}

    sched.run_action("creds.test")
    # the pair is confirmed (Pwn3d! → admin), recorded as a valid/admin cred
    assert fs.has("valid_cred") and fs.has("admin_cred")
    assert ("svc-alfresco", "s3rvice") in {(u, p) for u, p in fs._known_valid}


def test_crack_records_cred_pair_for_targeted_test(tmp_path, monkeypatch):
    from lib.engine.action import Tier
    from lib import crack
    monkeypatch.setattr(crack, "crack_hashes",
                        lambda ws, r, f, a: [("svc-alfresco", "s3rvice")])
    fs, posture, reg, sched = _setup(tmp_path, Tier.PASSIVE, tools=_ALL_TOOLS)
    fs.add_hash("asrep")

    sched.run_action("crack.hashes")
    assert fs.has("cred_pair")
    assert ("svc-alfresco", "s3rvice") in set(fs.snapshot()["cred_pairs"])


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


# ── Slice 4: tiered discovery, dedup, per-port version detect ─────────────────
def test_version_detect_dedups_sibling_ports(tmp_path):
    from lib.engine.action import Tier
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN, tools=_ALL_TOOLS)
    for p in (139, 445, 389, 3268, 636, 22):
        fs.add_open_port("tcp", p)
    vd_ports = sorted(args["port"]
                      for a, args in reg.available(fs, posture, sched.tried)
                      if a.name == "svc.version_detect")
    # 139 collapses into 445; 3268/636 collapse into 389; 22 stands alone
    assert vd_ports == [22, 389, 445]


def test_full_sweep_excludes_quick_scanned_ports(tmp_path, monkeypatch):
    from lib.engine.action import Tier
    from lib import nmap
    seen = {}
    monkeypatch.setattr(nmap, "discover_tcp_quick", lambda ip, r, ws: [445])

    def fake_full(ip, r, ws, exclude=None):
        seen["exclude"] = set(exclude or set())
        return [9999]
    monkeypatch.setattr(nmap, "discover_tcp_open", fake_full)

    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN, tools=_ALL_TOOLS)
    sched.run_action("discovery.tcp_quick")          # records the curated ports
    sched.run_action("discovery.tcp_ports")          # full sweep
    # the full sweep was told to skip the quick tier's ports
    assert 445 in seen["exclude"] and 22 in seen["exclude"]


def test_run_single_version_detect_instance(tmp_path, monkeypatch):
    from lib.engine.action import Tier
    from lib import nmap
    from lib.models import Service
    monkeypatch.setattr(nmap, "version_detect",
                        lambda ip, ports, r, ws: [Service(ports[0], "tcp", "x", "", False, "")])
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN, tools=_ALL_TOOLS)
    fs.add_open_port("tcp", 22)
    fs.add_open_port("tcp", 445)

    n = sched.run_action("svc.version_detect", port=445)
    assert n == 1
    assert instance_key("svc.version_detect", {"port": 445}) in sched.tried
    assert instance_key("svc.version_detect", {"port": 22}) not in sched.tried


def test_crack_marks_hash_cracked_and_closes_action(tmp_path, monkeypatch):
    from lib.engine.action import Tier
    from lib import crack
    monkeypatch.setattr(crack, "crack_hashes",
                        lambda ws, r, f, a: [("svc-alfresco", "s3rvice")])
    fs, posture, reg, sched = _setup(tmp_path, Tier.PASSIVE, tools=_ALL_TOOLS)
    fs.add_hash("asrep", "svc-alfresco")
    assert "crack.hashes" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}

    sched.run_action("crack.hashes")
    # hash flipped to cracked → crack.hashes no longer offered
    assert not fs.has("hash:uncracked")
    assert fs.snapshot()["hashes"][0]["plaintext"] == "s3rvice"
    assert "crack.hashes" not in {a.name for a, _ in reg.available(fs, posture, sched.tried)}


def test_phase4_actions_registered(tmp_path):
    reg = build_registry()
    names = {a.name for a in reg.all()}
    assert {"discovery.tcp_common", "kerberos.userenum"} <= names


def test_tcp_common_records_coverage(tmp_path, monkeypatch):
    from lib.engine.action import Tier
    from lib import nmap
    monkeypatch.setattr(nmap, "discover_tcp_common", lambda ip, r, ws: [22, 80])
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN, tools=_ALL_TOOLS)
    sched.run_action("discovery.tcp_common")
    assert fs.has("tcp/22") and fs.has("tcp/80")
    assert 22 in fs.scanned_tcp()


def test_ldap_branch_decomposed_into_cohesive_actions(tmp_path, monkeypatch):
    from lib import services
    from lib.engine.action import Tier
    calls = []
    for fn in ("_ldap_domain_info", "_ldap_users", "_ldap_groups", "_ldap_delegation"):
        monkeypatch.setattr(services, fn,
                            (lambda name: lambda ip, svc, r, f, a: calls.append(name))(fn))
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN, tools=_ALL_TOOLS)

    ldap_actions = {"ldap.domain_info", "ldap.users", "ldap.groups", "ldap.delegation"}
    assert "ldap.anon_bind" not in {a.name for a in reg.all()}     # monolith gone
    assert ldap_actions <= {a.name for a, _ in reg.dormant(fs)}    # need an LDAP port

    fs.add_open_port("tcp", 389)
    # `run ldap` runs the whole branch
    n = sched.run_group("ldap")
    assert n == 4
    assert set(calls) == {"_ldap_domain_info", "_ldap_users",
                          "_ldap_groups", "_ldap_delegation"}


def test_smb_branch_group_runs_all_four(tmp_path, monkeypatch):
    from lib import services
    from lib.engine.action import Tier
    calls = []
    for fn in ("_smb_users", "_smb_shares", "_smb_spider_shares", "_smb_policy"):
        monkeypatch.setattr(services, fn,
                            (lambda name: lambda ip, port, r, buf, a: calls.append(name))(fn))
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN, tools=_ALL_TOOLS)
    fs.add_open_port("tcp", 445)

    n = sched.run_group("smb")
    assert n == 4
    assert set(calls) == {"_smb_users", "_smb_shares", "_smb_spider_shares", "_smb_policy"}


def test_smb_policy_parses_lockout_and_sets_fact(tmp_path):
    from lib.engine.action import Tier
    out = ("SMB 10.0.0.1 445 DC [+] Dumping password info for domain: CORP\n"
           "SMB 10.0.0.1 445 DC Minimum password length: 7\n"
           "SMB 10.0.0.1 445 DC Account Lockout Threshold: None\n")
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN, output=out, tools=_ALL_TOOLS)
    fs.add_open_port("tcp", 445)
    sched.run_action("smb.policy")
    assert fs.snapshot()["lockout"] == 0             # "None" → 0, propagated to status


def test_smb_policy_notes_when_not_readable(tmp_path):
    from lib.engine.action import Tier
    # only the nxc banner, no policy → must NOT invent a lockout fact
    out = "SMB 10.0.0.1 445 DC [*] Windows (name:DC) (domain:corp) (Null Auth:True)\n"
    fs, posture, reg, sched = _setup(tmp_path, Tier.GREEN, output=out, tools=_ALL_TOOLS)
    fs.add_open_port("tcp", 445)
    sched.run_action("smb.policy")
    assert fs.snapshot()["lockout"] == -1            # still unknown
