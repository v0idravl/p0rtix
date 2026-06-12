from lib.engine.facts import FactStore, FactEvent, ProtoStatus
from lib.models import Service


def _store(tmp_path, domain=None):
    return FactStore("192.0.2.10", domain, "facts-test", str(tmp_path))


def _collect(store):
    events = []
    store.subscribe(events.append)
    return events


def test_add_user_emits_once_dedup_silent(tmp_path):
    fs = _store(tmp_path)
    events = _collect(fs)

    fs.add_user("alice")
    fs.add_user("alice")          # dedup — no event

    kinds = [(e.kind, e.value) for e in events]
    assert ("user", "alice") in kinds
    assert kinds.count(("user", "alice")) == 1
    # first user also flips the aggregate "users" fact exactly once
    assert kinds.count(("users", True)) == 1


def test_domain_and_lockout_are_first_write_wins(tmp_path):
    fs = _store(tmp_path)
    events = _collect(fs)

    fs.set_discovered_domain("test.htb")
    fs.set_discovered_domain("other.htb")     # ignored, no event
    fs.set_lockout_threshold(0)
    fs.set_lockout_threshold(5)               # ignored, no event

    assert fs.discovered_domain == "test.htb"
    assert fs.lockout_threshold == 0
    domain_events = [e for e in events if e.kind == "domain"]
    lockout_events = [e for e in events if e.kind == "lockout"]
    assert [e.value for e in domain_events] == ["test.htb"]
    assert [e.value for e in lockout_events] == [0]


def test_has_answers_named_facts(tmp_path):
    fs = _store(tmp_path)
    assert fs.has("domain") is False
    assert fs.has("users") is False
    assert fs.has("tcp/445") is False

    fs.set_discovered_domain("test.htb")
    fs.add_user("bob")
    fs.add_open_port("tcp", 445)
    fs.add_valid_cred("bob", "Pass1", "smb")

    assert fs.has("domain") is True
    assert fs.has("users") is True
    assert fs.has("valid_cred") is True
    assert fs.has("tcp/445") is True
    assert fs.has("udp/161") is False
    assert fs.has("lockout_known") is False


def test_admin_cred_unlocks_and_is_also_valid(tmp_path):
    fs = _store(tmp_path)
    events = _collect(fs)
    fs.add_admin_cred("administrator", "Hunter2")
    kinds = {e.kind for e in events}
    assert "admin_cred" in kinds
    assert "valid_cred" in kinds          # admin is also a valid cred
    assert fs.has("admin_cred") is True
    assert fs.has("valid_cred") is True


def test_open_ports_and_services_emit(tmp_path):
    fs = _store(tmp_path)
    events = _collect(fs)
    fs.add_open_port("tcp", 80)
    fs.add_open_port("tcp", 80)           # dedup
    svc = [Service(445, "tcp", "microsoft-ds", "", False, "")]
    fs.set_services(svc)

    port_events = [e for e in events if e.kind == "port_open"]
    assert port_events == [FactEvent("port_open", ("tcp", 80))]
    assert any(e.kind == "service" for e in events)
    assert fs.has("tcp/445") is True       # set_services also registers the port


def test_proto_status_emits_on_change_only(tmp_path):
    fs = _store(tmp_path)
    events = _collect(fs)
    fs.set_proto_status("ldap", ProtoStatus.ANON_DENIED)
    fs.set_proto_status("ldap", ProtoStatus.ANON_DENIED)   # same — no event
    fs.set_proto_status("ldap", ProtoStatus.NEEDS_CREDS)
    status_events = [e for e in events if e.kind == "proto_status"]
    assert len(status_events) == 2
    assert fs.proto_status("ldap") is ProtoStatus.NEEDS_CREDS


def test_listener_runs_outside_lock_no_deadlock(tmp_path):
    fs = _store(tmp_path)
    seen = []

    def listener(ev):
        # Re-enter the store from inside a listener: must not deadlock.
        seen.append(fs.snapshot()["users"])

    fs.subscribe(listener)
    fs.add_user("carol")     # would hang if listeners fired under the user lock
    assert seen and "carol" in seen[-1]


def test_workspace_collect_once_semantics_preserved(tmp_path):
    fs = _store(tmp_path)
    fs.add_user("seeded")                       # unverified (e.g. --users)
    fs.add_user("fromldap", authoritative=True) # directory-confirmed
    assert fs.unverified_users() == ["seeded"]
    assert fs.users_complete is False
    fs.mark_users_complete()
    assert fs.users_complete is True


def test_reload_picks_up_external_edits(tmp_path):
    fs = _store(tmp_path)
    fs.add_user("alice")
    events = _collect(fs)

    # Simulate the operator editing loot/users.txt out-of-band.
    users_file = fs.loot_dir / "users.txt"
    users_file.write_text("alice\nbob\ncharlie\n")

    new = fs.reload()
    assert new == 2                              # bob + charlie are new
    new_users = {e.value for e in events if e.kind == "user"}
    assert new_users == {"bob", "charlie"}       # alice already known — silent


# ── Slice 5: hash crack-state model ───────────────────────────────────────────
def test_hash_tracks_cracked_state(tmp_path):
    fs = FactStore("10.0.0.1", None, "hash-test", str(tmp_path))
    fs.add_hash("asrep", "svc-alfresco")
    assert fs.has("hash") and fs.has("hash:uncracked") and fs.has("hash:asrep")

    h = fs.snapshot()["hashes"][0]
    assert h == {"kind": "asrep", "principal": "svc-alfresco",
                 "cracked": False, "plaintext": None}

    fs.mark_hash_cracked("svc-alfresco", "s3rvice")
    assert not fs.has("hash:uncracked")          # nothing left to crack
    h = fs.snapshot()["hashes"][0]
    assert h["cracked"] and h["plaintext"] == "s3rvice"


def test_hash_cracked_event_emitted(tmp_path):
    fs = FactStore("10.0.0.1", None, "hash-ev", str(tmp_path))
    events = []
    fs.subscribe(lambda ev: events.append(ev.kind))
    fs.add_hash("kerberoast", "sqlsvc")
    fs.mark_hash_cracked("sqlsvc", "Summer2024")
    assert events.count("hash") == 2             # capture + crack both notify
