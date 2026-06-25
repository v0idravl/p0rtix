"""
Recon breadth — the concise→broad knob, analogous to the port tiers.

Just as port discovery climbs quick → common → full, breadth scales how hard a
brute/guess effort tries: CONCISE is fast and surgical, BROAD leaves no stone
unturned (and takes far longer). It is orthogonal to the noise ladder — a BROAD
wordlist at GREEN noise is legitimate (thorough, not intrusive).

Today this drives offline crack effort (straight rockyou → +best64 → +big-rule).
Web dir/vhost wordlist tiering plugs into the same `Breadth` once those call
sites take it. Resolution is graceful: a missing rule file falls back to a
smaller one rather than failing.
"""
from __future__ import annotations

import enum
from pathlib import Path


class Breadth(enum.Enum):
    CONCISE = "concise"     # fast, surgical — straight dictionary, no rules
    STANDARD = "standard"   # a light rule pass (best64) — the sensible default
    BROAD = "broad"         # leave no stone unturned — a large rule set (slow)

    @property
    def label(self) -> str:
        return self.value


def parse_breadth(value, default: Breadth = Breadth.STANDARD) -> Breadth:
    """Coerce a string / Breadth into a Breadth, falling back to `default`."""
    if isinstance(value, Breadth):
        return value
    if not value:
        return default
    try:
        return Breadth(str(value).strip().lower())
    except ValueError:
        return default


# hashcat rule files by breadth, in preference order. Resolution falls back to a
# smaller set when the preferred file is absent, so a thin box still cracks.
_RULE_CANDIDATES: dict[Breadth, list[str]] = {
    Breadth.STANDARD: [
        "/usr/share/hashcat/rules/best64.rule",
    ],
    Breadth.BROAD: [
        "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
        "/usr/share/seclists/Passwords/L0phtCrack/L0phtCrack.rule",
        "/usr/share/hashcat/rules/dive.rule",
        "/usr/share/hashcat/rules/d3ad0ne.rule",
        "/usr/share/hashcat/rules/best64.rule",   # last-resort fallback
    ],
}


def crack_rule_file(breadth: Breadth) -> str | None:
    """Return a hashcat `-r` rule file for this breadth, or None for a straight
    dictionary run (CONCISE, or when no rule file is installed)."""
    if breadth is Breadth.CONCISE:
        return None
    for p in _RULE_CANDIDATES.get(breadth, []):
        if Path(p).is_file():
            return p
    if breadth is Breadth.BROAD:                      # graceful step-down
        for p in _RULE_CANDIDATES[Breadth.STANDARD]:
            if Path(p).is_file():
                return p
    return None


# ── web fuzzing wordlists, tiered by breadth ──────────────────────────────────
_SECLISTS = "/usr/share/seclists"

# kind → breadth → candidate paths (preference order). CONCISE is small/fast,
# BROAD is large/thorough. Resolution steps *down* across breadths when a file is
# absent, so a thin SecLists install still fuzzes with whatever it has.
_WEB_WORDLISTS: dict[str, dict[Breadth, list[str]]] = {
    "dirs": {
        Breadth.CONCISE:  [f"{_SECLISTS}/Discovery/Web-Content/raft-small-directories.txt"],
        Breadth.STANDARD: [f"{_SECLISTS}/Discovery/Web-Content/common.txt"],
        Breadth.BROAD: [
            f"{_SECLISTS}/Discovery/Web-Content/directory-list-2.3-medium.txt",
            f"{_SECLISTS}/Discovery/Web-Content/raft-large-directories.txt",
        ],
    },
    "vhost": {
        Breadth.CONCISE:  [f"{_SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt"],
        Breadth.STANDARD: [f"{_SECLISTS}/Discovery/DNS/subdomains-top1million-5000.txt"],
        Breadth.BROAD: [
            f"{_SECLISTS}/Discovery/DNS/subdomains-top1million-110000.txt",
            f"{_SECLISTS}/Discovery/DNS/subdomains-top1million-20000.txt",
        ],
    },
    "api": {
        Breadth.CONCISE:  [f"{_SECLISTS}/Discovery/Web-Content/api/objects.txt"],
        Breadth.STANDARD: [f"{_SECLISTS}/Discovery/Web-Content/api/objects.txt"],
        Breadth.BROAD: [
            f"{_SECLISTS}/Discovery/Web-Content/api/api-endpoints.txt",
            f"{_SECLISTS}/Discovery/Web-Content/api/objects.txt",
        ],
    },
}

_STEPDOWN = {
    Breadth.BROAD:    [Breadth.BROAD, Breadth.STANDARD, Breadth.CONCISE],
    Breadth.STANDARD: [Breadth.STANDARD, Breadth.CONCISE],
    Breadth.CONCISE:  [Breadth.CONCISE, Breadth.STANDARD],
}


def web_wordlist(kind: str, breadth: Breadth) -> str | None:
    """A wordlist path for a web fuzz of `kind` ("dirs"|"vhost"|"api") at this
    breadth, or None if none is installed. Falls back across breadths (preferred
    → smaller) and within each breadth's candidate list."""
    tiers = _WEB_WORDLISTS.get(kind, {})
    for b in _STEPDOWN[breadth]:
        for p in tiers.get(b, []):
            if Path(p).is_file():
                return p
    return None
