"""IKE PSK offline cracking (psk-crack backend) — `_crack_ike_psk`,
`_ikepsk_principals`, and `crack_hashes` invoking the psk-crack backend.

Uses the REAL FactStore on a tmp workspace so add_hash / mark_hash_cracked /
snapshot / add_cred behave correctly, and a fake runner/findings matching the
patterns in tests/test_wordlists_crack.py.
"""
from lib import crack
from lib.engine.facts import FactStore
from lib.wordlists import Breadth


# Canned psk-crack hit (the form `_PSK_HIT_RE` parses).
_PSK_OUT = (
    "Starting psk-crack\n"
    "Running in dictionary cracking mode\n"
    'key "freakingrockstarontheroad" matches SHA1 hash '
    "316148cc871b30bde17ac07cbad9b7ab099e4fbe\n"
    "Ending psk-crack\n"
)


class _FakeRunner:
    """`.run(cmd, label, timeout=...)` → canned psk-crack output for psk-crack,
    "" otherwise. Records every command for assertions."""

    def __init__(self):
        self.cmds = []

    def run(self, cmd, *a, **k):
        self.cmds.append(cmd)
        if cmd and cmd[0] == "psk-crack":
            return _PSK_OUT
        return ""


class _FakeFindings:
    """Accepts the surface `_crack_ike_psk` / hashcat paths use; records notes."""

    def __init__(self):
        self.notes = []
        self.bullets = []

    def h2(self, *a, **k): pass
    def h4(self, *a, **k): pass
    def bullet(self, text, *a, **k): self.bullets.append(text)
    def cmd(self, *a, **k): pass
    def note(self, text, *a, **k): self.notes.append(text)
    def add_summary(self, *a, **k): pass
    def code_block(self, *a, **k): pass


def _ws_with_psk(tmp_path, *, principal="ike", content="dummy-psk-params\n"):
    """A FactStore seeded with an IKE PSK hash and a non-empty ike_psk.txt."""
    ws = FactStore("10.0.0.1", None, "ikebox", str(tmp_path))
    ws.add_hash("ikepsk", principal)
    (ws.loot_dir / crack._IKE_PSK_FILE).write_text(content)
    return ws


# ── _ikepsk_principals ────────────────────────────────────────────────────────
def test_ikepsk_principals_lists_seeded_principal(tmp_path):
    ws = _ws_with_psk(tmp_path, principal="ike")
    assert crack._ikepsk_principals(ws) == ["ike"]


def test_ikepsk_principals_empty_when_no_ikepsk_hash(tmp_path):
    ws = FactStore("10.0.0.1", None, "ikebox", str(tmp_path))
    assert crack._ikepsk_principals(ws) == []


# ── _crack_ike_psk: absent / empty file ───────────────────────────────────────
def test_crack_ike_psk_no_file_returns_empty_no_call(tmp_path):
    ws = FactStore("10.0.0.1", None, "ikebox", str(tmp_path))  # no ike_psk.txt
    r = _FakeRunner()
    assert crack._crack_ike_psk(ws, r, _FakeFindings(), {"psk-crack"}) == []
    assert r.cmds == []                                        # no psk-crack call


def test_crack_ike_psk_empty_file_returns_empty_no_call(tmp_path):
    ws = _ws_with_psk(tmp_path, content="")                    # present but empty
    r = _FakeRunner()
    assert crack._crack_ike_psk(ws, r, _FakeFindings(), {"psk-crack"}) == []
    assert r.cmds == []


# ── _crack_ike_psk: tool missing ──────────────────────────────────────────────
def test_crack_ike_psk_tool_missing_notes_and_returns_empty(tmp_path):
    ws = _ws_with_psk(tmp_path)
    r = _FakeRunner()
    f = _FakeFindings()
    assert crack._crack_ike_psk(ws, r, f, set()) == []         # psk-crack absent
    assert r.cmds == []                                        # never invoked
    assert any("psk-crack" in n for n in f.notes)              # emitted a note


# ── _crack_ike_psk: happy path ────────────────────────────────────────────────
def test_crack_ike_psk_cracks_and_marks(tmp_path, monkeypatch):
    ws = _ws_with_psk(tmp_path, principal="ike")
    wl = tmp_path / "rockyou.txt"
    wl.write_text("freakingrockstarontheroad\n")
    monkeypatch.setattr(crack, "_find_rockyou", lambda: str(wl))

    r = _FakeRunner()
    out = crack._crack_ike_psk(ws, r, _FakeFindings(), {"psk-crack"})

    assert out == [("ike", "freakingrockstarontheroad")]

    # psk-crack invoked as `psk-crack -d <wordlist> <file>`
    psk_cmd = next(c for c in r.cmds if c and c[0] == "psk-crack")
    assert psk_cmd[1] == "-d"
    assert psk_cmd[2] == str(wl)
    assert psk_cmd[3].endswith(crack._IKE_PSK_FILE)

    snap = ws.snapshot()
    ike = next(h for h in snap["hashes"] if h["kind"] == "ikepsk")
    assert ike["cracked"] is True
    assert ike["plaintext"] == "freakingrockstarontheroad"
    assert "freakingrockstarontheroad" in snap["creds"]


def test_crack_ike_psk_no_principal_marks_bare(tmp_path, monkeypatch):
    # IKE PSK file present but no ikepsk hash/principal in the fact store.
    ws = FactStore("10.0.0.1", None, "ikebox", str(tmp_path))
    (ws.loot_dir / crack._IKE_PSK_FILE).write_text("dummy\n")
    wl = tmp_path / "rockyou.txt"
    wl.write_text("freakingrockstarontheroad\n")
    monkeypatch.setattr(crack, "_find_rockyou", lambda: str(wl))

    out = crack._crack_ike_psk(ws, _FakeRunner(), _FakeFindings(), {"psk-crack"})
    assert out == [("", "freakingrockstarontheroad")]
    assert "freakingrockstarontheroad" in ws.snapshot()["creds"]


# ── crack_hashes: psk-crack backend without hashcat ───────────────────────────
def test_crack_hashes_cracks_ike_psk_without_hashcat(tmp_path, monkeypatch):
    """An IKE-PSK-only box cracks via psk-crack even when hashcat is absent."""
    ws = _ws_with_psk(tmp_path, principal="ike")
    wl = tmp_path / "rockyou.txt"
    wl.write_text("freakingrockstarontheroad\n")
    monkeypatch.setattr(crack, "_find_rockyou", lambda: str(wl))

    out = crack.crack_hashes(ws, _FakeRunner(), _FakeFindings(),
                             {"psk-crack"}, Breadth.CONCISE)
    assert ("ike", "freakingrockstarontheroad") in out
    assert ws.snapshot()["hashes"][0]["cracked"] is True
