"""MCP session tests — the generic engine-mirror surface.

No external tools run: nmap/service calls are monkeypatched, exactly like the
console smoke tests. These cover the snapshot-diff (`facts_delta`), the handoff
shape, posture gating, fact seeding, and that a blocked/dormant action returns a
`why` instead of dispatching."""
from types import SimpleNamespace

import pytest

from lib import nmap, services
from lib.mcp.session import McpSession, SessionManager, snapshot_diff


def _args(tmp_path, **over):
    base = dict(workspace=str(tmp_path), deep=False, users=None, level=0, headless=True)
    base.update(over)
    return SimpleNamespace(**base)


def _session(tmp_path, **over):
    return McpSession("192.0.2.10", over.pop("domain", "contoso.local"),
                      "mcp", _args(tmp_path, **over),
                      available={"nmap", "nxc", "ldapsearch"})


# ── SessionManager (static registration → open_target) ────────────────────────
def test_manager_has_no_current_until_open(tmp_path):
    mgr = SessionManager(_args(tmp_path), available={"nmap"})
    assert mgr.current is None
    s = mgr.open("10.0.0.5", "corp.local", "boxA")
    assert mgr.current is s
    assert s.get_state()["target"] == "10.0.0.5"
    assert s.get_state()["domain"] == "corp.local"


def test_manager_reopen_resumes_same_session(tmp_path):
    mgr = SessionManager(_args(tmp_path), available={"nmap"})
    s1 = mgr.open("10.0.0.5", None, "boxA")
    s1.facts.add_user("alice")
    s2 = mgr.open("10.0.0.5", None, "boxA")          # same key → same session
    assert s2 is s1
    assert "alice" in s2.get_state()["users"]


def test_manager_switches_between_targets(tmp_path):
    mgr = SessionManager(_args(tmp_path), available={"nmap"})
    mgr.open("10.0.0.5", None, "boxA")
    mgr.open("10.0.0.6", None, "boxB")
    assert mgr.current.get_state()["target"] == "10.0.0.6"
    assert set(mgr.targets()) == {"10.0.0.5/boxA", "10.0.0.6/boxB"}


# ── snapshot diff ─────────────────────────────────────────────────────────────
def test_snapshot_diff_reports_new_facts(tmp_path):
    s = _session(tmp_path)
    before = s.facts.snapshot()
    s.facts.add_user("administrator")
    s.facts.add_open_port("tcp", 445)
    s.facts.add_valid_cred("svc", "Pass1", "manual")
    after = s.facts.snapshot()

    delta = snapshot_diff(before, after)
    assert "administrator" in delta["users"]
    assert ["tcp", 445] in delta["open_ports"]
    assert ["svc", "Pass1"] in delta["valid_creds"]


def test_snapshot_diff_empty_when_nothing_changes(tmp_path):
    s = _session(tmp_path)
    snap = s.facts.snapshot()
    assert snapshot_diff(snap, snap) == {}


# ── inspection ────────────────────────────────────────────────────────────────
def test_get_state_reports_posture_and_seeded_domain(tmp_path):
    s = _session(tmp_path)
    st = s.get_state()
    assert st["target"] == "192.0.2.10"
    assert st["domain"] == "contoso.local"
    assert st["posture"] == "passive"
    assert st["open_ports"] == []


def test_list_actions_classifies_state_and_is_json_safe(tmp_path):
    s = _session(tmp_path)
    rows = s.list_actions()
    by_name = {r["name"]: r for r in rows}
    # discovery is gate-open but PASSIVE posture blocks green-tier actions
    assert by_name["discovery.tcp_quick"]["state"] == "blocked"
    assert by_name["discovery.tcp_quick"]["tier"] == "green"
    # every row carries a one-line reason
    assert all(r["why"] for r in rows)


# ── posture ───────────────────────────────────────────────────────────────────
def test_set_noise_raises_and_unblocks(tmp_path):
    s = _session(tmp_path)
    assert s.set_noise("green") == {"ok": True, "noise": "green"}
    s.facts.add_open_port("tcp", 445)
    smb = [r for r in s.list_actions() if r["name"] == "smb.users"][0]
    assert smb["state"] == "available"


def test_red_is_locked_until_armed(tmp_path):
    s = _session(tmp_path)
    assert s.set_noise("red")["ok"] is False
    assert s.arm_dangerous() == {"ok": True, "red_unlocked": True}
    assert s.set_noise("red") == {"ok": True, "noise": "red"}


def test_set_breadth_is_orthogonal_to_noise(tmp_path):
    s = _session(tmp_path)
    assert s.get_state()["breadth"] == "standard"        # sensible default
    assert s.set_breadth("broad") == {"ok": True, "breadth": "broad"}
    assert s.get_state()["breadth"] == "broad"
    assert s.get_state()["posture"] == "passive"         # noise unchanged
    assert s.set_breadth("bogus")["ok"] is False


def test_versioned_services_surface_in_state_delta_and_handoff(tmp_path):
    """The service product/version (e.g. 'HttpFileServer httpd 2.3') must be
    structured, not just in findings_md — it's the exploit-selection signal for
    the metasploit handoff. Regression for the Optimum/HFS live test."""
    from lib.models import Service
    s = _session(tmp_path)
    before = s.facts.snapshot()
    s.facts.add_services([Service(80, "tcp", "http", "HttpFileServer httpd 2.3",
                                  is_web=True, scheme="http")])
    after = s.facts.snapshot()

    delta = snapshot_diff(before, after)
    assert delta["services"][0]["version"] == "HttpFileServer httpd 2.3"
    assert s.get_state()["services"][0]["name"] == "http"
    h = s.export_handoff()
    assert {"port": 80, "proto": "tcp", "name": "http",
            "version": "HttpFileServer httpd 2.3"} in h["services"]


def test_web_tech_surfaces_in_state_delta_and_handoff(tmp_path):
    """Web fingerprint tech (Server header, whatweb) must be structured, not only
    in findings_md — so the driving agent sees it via facts_delta/get_state and it
    rides along in the handoff. Regression for the Optimum web-blindness delta."""
    s = _session(tmp_path)
    before = s.facts.snapshot()
    s.facts.add_web_tech(80, "HFS 2.3")
    s.facts.add_web_tech(80, "JQuery 1.4.4")
    after = s.facts.snapshot()

    delta = snapshot_diff(before, after)
    techs = {(x["port"], x["tech"]) for x in delta["web_tech"]}
    assert (80, "HFS 2.3") in techs and (80, "JQuery 1.4.4") in techs
    assert {"port": 80, "tech": "HFS 2.3"} in s.get_state()["web_tech"]
    assert {"port": 80, "tech": "HFS 2.3"} in s.export_handoff()["web_tech"]


def test_exploit_candidates_in_state_and_handoff(tmp_path):
    """A known-RCE service (HFS 2.3 → CVE-2014-6287) yields a structured exploit
    candidate with an msf module in both get_state and export_handoff."""
    from lib.models import Service
    s = _session(tmp_path)
    s.facts.add_services([Service(80, "tcp", "http", "HttpFileServer httpd 2.3",
                                  is_web=True, scheme="http")])
    cand = s.export_handoff()["exploit_candidates"]
    assert any(c["cve"] == "CVE-2014-6287"
               and c["msf_module"] == "exploit/windows/http/rejetto_hfs_exec"
               and c["port"] == 80 for c in cand)
    assert s.get_state()["exploit_candidates"] == cand


def test_run_group_aggregates_findings_md_and_actions(tmp_path, monkeypatch):
    """run_group must surface every sub-action's rendered findings + summaries —
    not return an empty body — so a bulk web/smb run is not blind over MCP."""
    def fake_users(ip, port, runner, buf, available):
        buf.bullet("user roster: alice, bob")

    def fake_shares(ip, port, runner, buf, available):
        buf.bullet("readable share: NETLOGON")

    monkeypatch.setattr(services, "_smb_users", fake_users)
    monkeypatch.setattr(services, "_smb_shares", fake_shares)
    for fn in ("_smb_spider_shares", "_smb_policy"):
        monkeypatch.setattr(services, fn, lambda *a, **k: None)
    monkeypatch.setattr("lib.runner.Runner.run", lambda self, *a, **k: "")

    s = _session(tmp_path)
    s.set_noise("green")
    s.facts.add_open_port("tcp", 445)
    res = s.run_group("smb")
    assert res["dispatched"] >= 2
    assert "user roster: alice, bob" in res["findings_md"]
    assert "readable share: NETLOGON" in res["findings_md"]
    assert {a["action"] for a in res["actions"]} >= {"smb.users", "smb.shares"}


def test_collect_caps_oversized_findings_md(tmp_path):
    """A broad bulk run can concatenate >100 KB of per-action markdown and overflow
    the MCP tool-result token cap (the CozyHosting run_all failure). _collect must
    hard-cap the markdown while keeping the compact actions list intact."""
    from lib.mcp.session import _FINDINGS_MD_BUDGET
    s = _session(tmp_path)
    # Simulate many noisy captures past the budget.
    big = "x" * 2000
    for i in range(120):  # ~240 KB, well over the cap
        s._capture(f"act{i}", f"summary {i}", f"## finding {i}\n{big}")
    collected = s._collect(0)
    assert collected["findings_truncated"] is True
    assert collected["findings_chars"] > _FINDINGS_MD_BUDGET
    # capped to budget + a short truncation notice; never the full 240 KB
    assert len(collected["findings_md"]) < _FINDINGS_MD_BUDGET + 500
    assert "findings truncated" in collected["findings_md"]
    # the per-action map is NOT truncated — every action is still listed
    assert len(collected["actions"]) == 120
    assert collected["actions"][0]["action"] == "act0"


def test_collect_does_not_cap_small_findings_md(tmp_path):
    """A normal-sized result is returned whole with findings_truncated False."""
    s = _session(tmp_path)
    s._capture("smb.users", "2 users", "## SMB\nuser roster: alice, bob")
    collected = s._collect(0)
    assert collected["findings_truncated"] is False
    assert "alice, bob" in collected["findings_md"]
    assert "truncated" not in collected["findings_md"]


def test_run_group_explains_why_when_nothing_dispatched(tmp_path):
    """dispatched:0 must come with a per-action `why` (delta: 'should say why'),
    not a silent empty result — here SMB is dormant with no tcp/445 open."""
    s = _session(tmp_path)
    s.set_noise("green")
    res = s.run_group("smb")            # no SMB port → nothing available
    assert res["dispatched"] == 0
    why = {r["action"]: r["why"] for r in res["why"]}
    assert "smb.users" in why and "dormant" in why["smb.users"].lower()


def test_run_all_explains_why_when_nothing_dispatched(tmp_path):
    s = _session(tmp_path)              # PASSIVE, no facts → nothing green runs
    res = s.run_all()
    assert res["dispatched"] == 0
    assert "noise" in res["why"].lower() or "list_actions" in res["why"]


def test_version_detect_seeds_web_tech_for_web_service(tmp_path, monkeypatch):
    """A versioned web service must populate web_tech immediately, so the handoff
    isn't empty if the agent exports before a full web.enum pass (Optimum delta)."""
    from lib.models import Service
    monkeypatch.setattr(
        nmap, "version_detect",
        lambda ip, ports, r, ws: [Service(80, "tcp", "http",
                                          "HttpFileServer httpd 2.3",
                                          is_web=True, scheme="http")])
    s = _session(tmp_path)
    s.set_noise("green")
    s.facts.add_open_port("tcp", 80)
    s.run_action("svc.version_detect", port=80)
    assert {"port": 80, "tech": "HttpFileServer httpd 2.3"} in s.get_state()["web_tech"]


def test_handoff_flags_in_flight_full_scan(tmp_path, monkeypatch):
    """export_handoff carries full_scan_running so the agent knows ports may still
    be arriving and can re-export once the background sweep finishes."""
    import threading
    from lib import nmap
    gate = threading.Event()
    monkeypatch.setattr(nmap, "discover_tcp_open",
                        lambda ip, r, ws, exclude=None, live=True: (gate.wait(2), [22])[1])
    s = _session(tmp_path)
    assert s.export_handoff()["full_scan_running"] is False
    s.start_full_scan()
    assert s.export_handoff()["full_scan_running"] is True   # in-flight
    gate.set()
    for _ in range(100):
        if not s.background_status()["running"]:
            break
        import time; time.sleep(0.02)
    assert s.export_handoff()["full_scan_running"] is False


def test_background_full_scan_merges_ports(tmp_path, monkeypatch):
    """The background full-TCP sweep runs off the dispatch lock and lands new
    ports in the fact store; background_status reports completion."""
    import time
    from lib import nmap
    monkeypatch.setattr(nmap, "discover_tcp_open",
                        lambda ip, r, ws, exclude=None, live=True: [445, 3389])
    s = _session(tmp_path)
    assert s.background_status()["running"] is False
    assert s.start_full_scan()["status"] == "started"
    for _ in range(50):                       # let the daemon thread finish
        if not s.background_status()["running"]:
            break
        time.sleep(0.02)
    st = s.background_status()
    assert st["running"] is False and st.get("done") is True
    assert sorted(st["new_ports"]) == [445, 3389]
    assert ["tcp", 3389] in [list(p) for p in s.facts.snapshot()["open_ports"]]


def test_list_actions_exposes_web_and_service_groups(tmp_path):
    s = _session(tmp_path)
    groups = {r["group"] for r in s.list_actions()}
    assert {"web", "service"} <= groups                  # broadened beyond AD
    names = {r["name"] for r in s.list_actions()}
    assert "web.enum" in names and "service.enum" in names


# ── fact population ───────────────────────────────────────────────────────────
def test_add_fact_creds_seeds_user_and_cred(tmp_path):
    s = _session(tmp_path)
    assert s.add_fact("creds", "svc-web:Summer2024")["ok"] is True
    st = s.get_state()
    assert ["svc-web", "Summer2024"] in st["valid_creds"]
    assert "svc-web" in st["users"]


def test_add_fact_rejects_bad_creds_and_unknown_kind(tmp_path):
    s = _session(tmp_path)
    assert s.add_fact("creds", "no-colon")["ok"] is False
    assert s.add_fact("bogus", "x")["ok"] is False


# ── execution ─────────────────────────────────────────────────────────────────
def test_run_action_dormant_returns_why_not_dispatch(tmp_path):
    s = _session(tmp_path)
    s.set_noise("green")
    res = s.run_action("ldap.users")  # no LDAP port open → dormant
    assert res["ok"] is False
    assert res["dispatched"] == 0
    assert "needs" in res["why"].lower()


def test_run_action_dispatches_and_returns_facts_delta(tmp_path, monkeypatch):
    def fake_users(ip, port, runner, buf, available):
        runner.ws.add_user("alice", authoritative=True)
        buf.bullet("found alice")

    monkeypatch.setattr(services, "_smb_users", fake_users)
    s = _session(tmp_path)
    s.set_noise("green")
    s.facts.add_open_port("tcp", 445)

    res = s.run_action("smb.users")
    assert res["ok"] is True
    assert res["dispatched"] == 1
    assert "alice" in res["facts_delta"]["users"]
    assert "alice" in res["findings_md"]


def test_run_group_runs_branch(tmp_path, monkeypatch):
    for fn in ("_smb_users", "_smb_shares", "_smb_spider_shares", "_smb_policy"):
        monkeypatch.setattr(services, fn, lambda *a, **k: None)
    s = _session(tmp_path)
    s.set_noise("green")
    s.facts.add_open_port("tcp", 445)
    res = s.run_group("smb")
    assert res["ok"] is True
    assert res["dispatched"] >= 1


def test_run_all_cascades_from_discovery(tmp_path, monkeypatch):
    monkeypatch.setattr(nmap, "discover_tcp_quick", lambda ip, r, ws: [445])
    monkeypatch.setattr(nmap, "discover_tcp_common", lambda ip, r, ws, exclude=None: [])
    monkeypatch.setattr(nmap, "discover_tcp_open", lambda ip, r, ws, exclude=None: [445])
    monkeypatch.setattr(nmap, "discover_udp", lambda ip, r, ws: [])
    monkeypatch.setattr(nmap, "version_detect", lambda ip, ports, r, ws: [])
    for fn in ("_smb_users", "_smb_shares", "_smb_spider_shares", "_smb_policy"):
        monkeypatch.setattr(services, fn, lambda *a, **k: None)

    s = _session(tmp_path)
    res = s.run_all("green")
    assert res["ok"] is True
    assert res["dispatched"] >= 1
    assert ["tcp", 445] in res["facts_delta"].get("open_ports", [])


# ── access.exec via the generic run_action args passthrough ───────────────────
def test_run_action_threads_command_arg_to_access_exec(tmp_path, monkeypatch):
    from lib.engine import access
    seen = {}

    def fake_run(self, cmd, label, timeout=None):
        seen["cmd"] = cmd
        return "nt authority\\system"

    monkeypatch.setattr("lib.runner.Runner.run", fake_run)
    s = _session(tmp_path)
    s.arm_dangerous()
    s.set_noise("yellow")
    s.facts.add_open_port("tcp", 5985)
    s.facts.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    res = s.run_action("access.exec", args={"command": "whoami"})
    assert res["ok"] is True
    assert seen["cmd"][-2:] == ["-x", "whoami"]
    assert "system" in res["findings_md"].lower()


# ── handoff ───────────────────────────────────────────────────────────────────
def test_export_handoff_shape(tmp_path):
    s = _session(tmp_path)
    s.facts.add_open_port("tcp", 445)
    s.facts.add_admin_cred("administrator", "P@ss")
    s.facts.add_hash("kerberoast", "svc-sql", cracked=False)

    h = s.export_handoff()
    assert h["hosts"] == ["192.0.2.10"]
    assert h["domain"] == "contoso.local"
    assert {"proto": "tcp", "port": 445} in h["open_ports"]
    assert {"user": "administrator", "password": "P@ss"} in h["admin_creds"]
    assert {"user": "administrator", "password": "P@ss"} in h["valid_creds"]
    assert h["hashes"][0]["kind"] == "kerberoast"


# ── Baby deltas: stale-scan warning, cred_must_change, STATUS_PASSWORD_MUST_CHANGE

def test_stale_scan_warning_when_ports_empty_after_full_scan(tmp_path):
    """When scanned_tcp > 0 but open_ports is empty the scan ran against a
    terminated instance. get_state must surface a stale_scan_warning so the
    operator knows to recheck('discovery') rather than waiting forever (Baby)."""
    s = _session(tmp_path)
    # Simulate a completed full sweep with no ports found (stale instance)
    s.facts.add_scanned_tcp(range(1, 65536))
    assert s.facts.scanned_tcp()  # coverage is recorded
    assert not s.facts.snapshot()["open_ports"]  # but no ports

    st = s.get_state()
    assert "stale_scan_warning" in st
    assert "recheck" in st["stale_scan_warning"].lower()


def test_no_stale_scan_warning_when_ports_present(tmp_path):
    """When open_ports is populated there is no stale scan — no warning."""
    s = _session(tmp_path)
    s.facts.add_scanned_tcp(range(1, 65536))
    s.facts.add_open_port("tcp", 445)
    st = s.get_state()
    assert "stale_scan_warning" not in st


def test_no_stale_scan_warning_when_no_scan_run(tmp_path):
    """A fresh session (nothing scanned yet) must not trigger a stale warning."""
    s = _session(tmp_path)
    st = s.get_state()
    assert "stale_scan_warning" not in st


def test_cred_must_change_in_get_state_and_handoff(tmp_path):
    """STATUS_PASSWORD_MUST_CHANGE pairs surface in get_state and export_handoff
    (Baby delta: Caroline.Robinson was valid but expired)."""
    s = _session(tmp_path)
    s.facts.add_cred_must_change("Caroline.Robinson", "BabyStart123!")

    st = s.get_state()
    assert ["Caroline.Robinson", "BabyStart123!"] in st["cred_must_change"]
    # Not stored as a valid_cred in get_state
    assert ["Caroline.Robinson", "BabyStart123!"] not in st["valid_creds"]

    h = s.export_handoff()
    assert {"user": "Caroline.Robinson", "password": "BabyStart123!"} in h["cred_must_change"]
    assert {"user": "Caroline.Robinson", "password": "BabyStart123!"} not in h["valid_creds"]


def test_cred_must_change_in_snapshot_diff(tmp_path):
    """cred_must_change appears in snapshot_diff when new pairs are added."""
    from lib.mcp.session import snapshot_diff
    s = _session(tmp_path)
    before = s.facts.snapshot()
    s.facts.add_cred_must_change("Caroline.Robinson", "BabyStart123!")
    after = s.facts.snapshot()
    delta = snapshot_diff(before, after)
    assert "cred_must_change" in delta
    assert ["Caroline.Robinson", "BabyStart123!"] in delta["cred_must_change"]


def test_creds_test_detects_status_password_must_change(tmp_path, monkeypatch):
    """creds.test must detect STATUS_PASSWORD_MUST_CHANGE in nxc output and record
    it as a must-change fact, not ignore it like a plain LOGON_FAILURE (Baby)."""
    def fake_run(self, cmd, label, timeout=None):
        # Simulate nxc SMB returning STATUS_PASSWORD_MUST_CHANGE for Caroline.Robinson
        if "smb" in cmd and "Caroline.Robinson" in " ".join(cmd):
            return (
                "SMB  10.0.0.1  445  DC01  [-] DOMAIN\\Caroline.Robinson:BabyStart123! "
                "STATUS_PASSWORD_MUST_CHANGE"
            )
        return ""

    monkeypatch.setattr("lib.runner.Runner.run", fake_run)
    s = _session(tmp_path)
    s.set_noise("yellow")
    s.facts.add_open_port("tcp", 445)
    # Seed the credential pair so creds.test has something to test
    s.facts.add_cred_pair("Caroline.Robinson", "BabyStart123!")

    res = s.run_action("creds.test")
    assert res["ok"] is True
    # Must-change pair recorded in facts
    assert s.facts.has("cred_must_change")
    snap = s.facts.snapshot()
    assert ("Caroline.Robinson", "BabyStart123!") in snap["cred_must_change"]
    # NOT stored as a valid_cred
    assert ("Caroline.Robinson", "BabyStart123!") not in snap["valid_creds"]
    # Surfaced in findings
    assert "must" in res["findings_md"].lower() or "expired" in res["findings_md"].lower()
    # Summary mentions the expired credential
    assert "expired" in res["summary"].lower() or "must-change" in res["summary"].lower()
