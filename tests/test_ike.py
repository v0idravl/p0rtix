"""Unit tests for lib/ike.py — IKE / IPsec (ISAKMP) aggressive-mode recon.

Wires the REAL FactStore against a tmp workspace so add_user/add_hash/snapshot
behave for real, and drives enumerate_ike with a fake runner that returns
captured ike-scan output and writes a non-empty pskcrack file for the -A probe.
"""
from lib.engine.facts import FactStore
from lib.ike import enumerate_ike, _ingest_id


# Captured ike-scan output (verbatim) ─────────────────────────────────────────
MAIN_MODE_OUT = (
    "10.129.238.52\tMain Mode Handshake returned\n"
    "\tHDR=(CKY-R=63f741f679763d92)\n"
    "\tSA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)\n"
    "\tVID=09002689dfd6b712 (XAUTH)\n"
    "\tVID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)\n"
)

AGGRESSIVE_OUT = (
    "10.129.238.52\tAggressive Mode Handshake returned "
    "HDR=(CKY-R=1904f88c0f7f1272) "
    "SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) "
    "KeyExchange(128 bytes) Nonce(32 bytes) "
    "ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) "
    "VID=09002689dfd6b712 (XAUTH) Hash(20 bytes)\n"
)

# An aggressive reply leaking an ID_FQDN host identity instead of a user FQDN.
AGGRESSIVE_FQDN_OUT = (
    "10.129.238.52\tAggressive Mode Handshake returned "
    "HDR=(CKY-R=1904f88c0f7f1272) "
    "SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800) "
    "KeyExchange(128 bytes) Nonce(32 bytes) "
    "ID(Type=ID_FQDN, Value=gw.corp.local) "
    "VID=09002689dfd6b712 (XAUTH) Hash(20 bytes)\n"
)

# An aggressive probe that yields nothing (responder refuses aggressive mode).
AGGRESSIVE_EMPTY_OUT = (
    "10.129.238.52\tNotify message 14 (NO-PROPOSAL-CHOSEN)\n"
)


class FakeFindings:
    """Records the findings-sink calls; accepts every method ike.py uses."""

    def __init__(self):
        self.calls = []

    def h4(self, *a, **k):
        self.calls.append(("h4", a, k))

    def bullet(self, *a, **k):
        self.calls.append(("bullet", a, k))

    def cmd(self, *a, **k):
        self.calls.append(("cmd", a, k))

    def add_summary(self, *a, **k):
        self.calls.append(("add_summary", a, k))

    def note(self, *a, **k):
        self.calls.append(("note", a, k))


class FakeRunner:
    """Fake Runner: .ws is the FactStore, .run returns canned ike-scan text.

    Routes by command flag (-M → main mode, -A → aggressive). For the -A probe
    it also parses the --pskcrack=PATH argument and writes a non-empty hash file
    there, simulating ike-scan capturing the PSK to loot/.
    """

    def __init__(self, facts, aggressive_out=AGGRESSIVE_OUT,
                 main_out=MAIN_MODE_OUT, write_psk=True):
        self.ws = facts
        self._aggressive_out = aggressive_out
        self._main_out = main_out
        self._write_psk = write_psk
        self.calls = []

    def run(self, cmd, label, timeout=None):
        self.calls.append((list(cmd), label, timeout))
        if "-A" in cmd:
            for arg in cmd:
                if arg.startswith("--pskcrack="):
                    path = arg.split("=", 1)[1]
                    if self._write_psk:
                        with open(path, "w") as fh:
                            fh.write("ike@expressway.htb:deadbeefcafebabe:hashbytes\n")
            return self._aggressive_out
        if "-M" in cmd:
            return self._main_out
        return ""


def _store(tmp_path, domain=None):
    return FactStore("10.129.238.52", domain, "ike-test", str(tmp_path))


# ── enumerate_ike: full aggressive-mode chain (ID_USER_FQDN) ──────────────────
def test_aggressive_mode_leaks_user_domain_and_captures_psk(tmp_path):
    fs = _store(tmp_path)
    runner = FakeRunner(fs)
    findings = FakeFindings()

    result = enumerate_ike("10.129.238.52", runner, findings, {"ike-scan"})

    assert result["main_mode"] is True
    assert result["aggressive"] is True
    assert result["psk_auth"] is True
    assert result["psk_captured"] is True
    assert result["id"] == {
        "type": "ID_USER_FQDN",
        "value": "ike@expressway.htb",
        "user": "ike",
        "domain": "expressway.htb",
        "hostname": "",
    }

    snap = fs.snapshot()
    assert "ike" in snap["users"]
    assert fs.discovered_domain == "expressway.htb"
    assert any(h["kind"] == "ikepsk" and h["principal"] == "ike"
               for h in snap["hashes"])


def test_aggressive_runs_both_ike_scan_commands(tmp_path):
    fs = _store(tmp_path)
    runner = FakeRunner(fs)
    findings = FakeFindings()

    enumerate_ike("10.129.238.52", runner, findings, {"ike-scan"})

    assert len(runner.calls) == 2
    first_cmd = runner.calls[0][0]
    second_cmd = runner.calls[1][0]
    assert first_cmd == ["ike-scan", "-M", "10.129.238.52"]
    assert second_cmd[0] == "ike-scan"
    assert "-A" in second_cmd
    assert second_cmd[-1] == "10.129.238.52"
    assert any(a.startswith("--pskcrack=") for a in second_cmd)


def test_aggressive_adds_hostname_for_domain(tmp_path):
    fs = _store(tmp_path)
    runner = FakeRunner(fs)
    findings = FakeFindings()

    enumerate_ike("10.129.238.52", runner, findings, {"ike-scan"})

    # set_discovered_domain + add_hostname("expressway.htb") both fire.
    snap = fs.snapshot()
    assert "expressway.htb" in snap.get("hostnames", []) or \
        fs.discovered_domain == "expressway.htb"
    assert fs.discovered_domain == "expressway.htb"


# ── ID_FQDN host identity → hostname + parent domain ──────────────────────────
def test_aggressive_id_fqdn_yields_hostname_and_parent_domain(tmp_path):
    fs = _store(tmp_path)
    runner = FakeRunner(fs, aggressive_out=AGGRESSIVE_FQDN_OUT)
    findings = FakeFindings()

    result = enumerate_ike("10.129.238.52", runner, findings, {"ike-scan"})

    assert result["aggressive"] is True
    assert result["id"]["type"] == "ID_FQDN"
    assert result["id"]["value"] == "gw.corp.local"
    assert result["id"]["hostname"] == "gw.corp.local"
    assert result["id"]["domain"] == "corp.local"
    assert fs.discovered_domain == "corp.local"


# ── main-mode only: no aggressive handshake → no hash ─────────────────────────
def test_main_mode_only_no_psk_hash(tmp_path):
    fs = _store(tmp_path)
    runner = FakeRunner(fs, aggressive_out=AGGRESSIVE_EMPTY_OUT)
    findings = FakeFindings()

    result = enumerate_ike("10.129.238.52", runner, findings, {"ike-scan"})

    assert result["main_mode"] is True
    assert result["aggressive"] is False
    assert result["psk_captured"] is False
    assert result["id"] is None

    snap = fs.snapshot()
    assert not any(h["kind"] == "ikepsk" for h in snap["hashes"])
    assert "ike" not in snap["users"]


# ── ike-scan unavailable: early return, no runner calls ───────────────────────
def test_missing_ike_scan_returns_early(tmp_path):
    fs = _store(tmp_path)
    runner = FakeRunner(fs)
    findings = FakeFindings()

    result = enumerate_ike("10.129.238.52", runner, findings, set())

    assert result["main_mode"] is False
    assert result["aggressive"] is False
    assert runner.calls == []
    assert any(c[0] == "note" for c in findings.calls)


# ── _ingest_id helper, exercised directly ─────────────────────────────────────
def test_ingest_id_user_fqdn(tmp_path):
    fs = _store(tmp_path)
    findings = FakeFindings()

    out = _ingest_id(fs, "ID_USER_FQDN", "ike@expressway.htb", findings)

    assert out["user"] == "ike"
    assert out["domain"] == "expressway.htb"
    assert out["hostname"] == ""
    assert "ike" in fs.snapshot()["users"]
    assert fs.discovered_domain == "expressway.htb"


def test_ingest_id_fqdn(tmp_path):
    fs = _store(tmp_path)
    findings = FakeFindings()

    out = _ingest_id(fs, "ID_FQDN", "gw.corp.local", findings)

    assert out["hostname"] == "gw.corp.local"
    assert out["domain"] == "corp.local"
    assert out["user"] == ""
    assert fs.discovered_domain == "corp.local"


def test_ingest_id_other_type_mines_no_facts(tmp_path):
    fs = _store(tmp_path)
    findings = FakeFindings()

    out = _ingest_id(fs, "ID_IPV4_ADDR", "10.0.0.1", findings)

    assert out["user"] == ""
    assert out["domain"] == ""
    assert out["hostname"] == ""
    assert fs.snapshot()["users"] == [] or "10.0.0.1" not in fs.snapshot()["users"]
    assert fs.discovered_domain in (None, "")
