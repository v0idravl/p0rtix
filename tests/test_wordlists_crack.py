"""Breadth knob + crack rule tiering + web wordlist tiering (concise→broad)."""
from pathlib import Path

from lib import crack
from lib import wordlists
from lib.wordlists import Breadth, crack_rule_file, parse_breadth, web_wordlist


def test_parse_breadth_coerces_and_defaults():
    assert parse_breadth("broad") is Breadth.BROAD
    assert parse_breadth("CONCISE") is Breadth.CONCISE
    assert parse_breadth(Breadth.STANDARD) is Breadth.STANDARD
    assert parse_breadth(None) is Breadth.STANDARD            # default
    assert parse_breadth("nonsense", None) is None            # explicit failure


def test_concise_uses_no_rule_file():
    assert crack_rule_file(Breadth.CONCISE) is None


def test_standard_picks_best64_when_present(monkeypatch):
    monkeypatch.setattr(wordlists.Path, "is_file",
                        lambda self: self.name == "best64.rule")
    rf = crack_rule_file(Breadth.STANDARD)
    assert rf and Path(rf).name == "best64.rule"


def test_broad_steps_down_to_best64_when_big_rule_absent(monkeypatch):
    # only best64 exists → BROAD gracefully falls back to it
    monkeypatch.setattr(wordlists.Path, "is_file",
                        lambda self: self.name == "best64.rule")
    rf = crack_rule_file(Breadth.BROAD)
    assert rf and Path(rf).name == "best64.rule"


def test_broad_returns_none_when_no_rules_installed(monkeypatch):
    monkeypatch.setattr(wordlists.Path, "is_file", lambda self: False)
    assert crack_rule_file(Breadth.BROAD) is None


def test_crack_hashes_header_and_rule_arg_reflect_breadth(monkeypatch, tmp_path):
    """BROAD resolves a rule file → named in the header and passed to hashcat as
    `-r`; CONCISE does neither (straight dictionary run)."""
    from lib.findings import ServiceBuffer
    from lib.workspace import Workspace
    ws = Workspace("10.0.0.1", None, "crk", str(tmp_path))
    (ws.loot_dir / "kerberoast.hash").write_text("$krb5tgs$23$*svc$X*\n")
    monkeypatch.setattr(crack, "_find_rockyou", lambda: "/tmp/rockyou.txt")
    monkeypatch.setattr(crack, "crack_rule_file",
                        lambda b: "/usr/share/hashcat/rules/best64.rule"
                        if b is Breadth.BROAD else None)

    class _R:
        def __init__(self): self.cmds = []
        def run(self, cmd, *a, **k): self.cmds.append(cmd); return ""

    r = _R()
    buf = ServiceBuffer(0, "tcp")
    crack.crack_hashes(ws, r, buf, {"hashcat"}, Breadth.BROAD)
    rendered = buf.render()
    assert "best64.rule" in rendered
    attack = next(c for c in r.cmds if "-a" in c)            # the attack invocation
    assert "-r" in attack and "/usr/share/hashcat/rules/best64.rule" in attack

    r2 = _R()
    buf2 = ServiceBuffer(0, "tcp")
    crack.crack_hashes(ws, r2, buf2, {"hashcat"}, Breadth.CONCISE)
    assert "best64" not in buf2.render()
    assert all("-r" not in c for c in r2.cmds)               # no rule file


# ── web wordlist tiering ──────────────────────────────────────────────────────
def test_web_wordlist_picks_per_breadth(monkeypatch):
    # everything "installed" → each breadth gets its own preferred dir list
    monkeypatch.setattr(wordlists.Path, "is_file", lambda self: True)
    assert Path(web_wordlist("dirs", Breadth.CONCISE)).name == "raft-small-directories.txt"
    assert Path(web_wordlist("dirs", Breadth.STANDARD)).name == "common.txt"
    assert Path(web_wordlist("dirs", Breadth.BROAD)).name == "directory-list-2.3-medium.txt"


def test_web_wordlist_broad_steps_down_when_big_absent(monkeypatch):
    # only common.txt present → BROAD steps down to STANDARD's list
    monkeypatch.setattr(wordlists.Path, "is_file",
                        lambda self: self.name == "common.txt")
    assert Path(web_wordlist("dirs", Breadth.BROAD)).name == "common.txt"


def test_web_wordlist_none_when_nothing_installed(monkeypatch):
    monkeypatch.setattr(wordlists.Path, "is_file", lambda self: False)
    assert web_wordlist("dirs", Breadth.STANDARD) is None
    assert web_wordlist("vhost", Breadth.BROAD) is None


def test_dir_bust_uses_breadth_wordlist(monkeypatch):
    from lib import web
    from lib.findings import ServiceBuffer
    monkeypatch.setattr(web, "web_wordlist",
                        lambda kind, b: f"/wl/{kind}-{b.label}.txt")

    class _R:
        def __init__(self): self.cmds = []
        def run(self, cmd, *a, **k): self.cmds.append(cmd); return ""

    r = _R()
    buf = ServiceBuffer(0, "tcp")
    web._dir_bust("http://t", r, buf, {}, Breadth.BROAD)
    attack = r.cmds[0]
    assert "/wl/dirs-broad.txt" in attack
    assert "broad" in buf.render().lower()
