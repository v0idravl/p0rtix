import re
import threading
from datetime import date
from pathlib import Path

from lib.models import Service


def _slugify(value: str) -> str:
    return re.sub(r"[^a-z0-9._-]", "_", value.lower())


class Workspace:
    """
    Creates and owns the on-disk layout for a single scan session.

    Layout:
      <workspace>/<name>/
        findings.md       ← primary read surface (live-updated)
        report/report.md  ← writeup template
        loot/             ← credentials, hashes, files of interest
        exploit/          ← exploits, payloads
        raw/              ← full tool output with command headers
    """

    def __init__(self, ip: str, domain: str | None, name: str | None, workspace: str):
        self.ip = ip
        self.domain = domain

        slug = name if name else (domain if domain else ip)
        self.name = _slugify(slug)

        self.machine_dir = Path(workspace).resolve() / self.name
        self.raw_dir = self.machine_dir / "raw"
        self.loot_dir = self.machine_dir / "loot"
        self.exploit_dir = self.machine_dir / "exploit"
        self.report_dir = self.machine_dir / "report"
        self.findings_path = self.machine_dir / "findings.md"
        self.report_path = self.report_dir / "report.md"
        self.bloodhound_dir = self.loot_dir / "bloodhound"

        self._raw_counter = 0
        self._counter_lock = threading.Lock()
        self._known_users: set[str] = set()
        self._users_lock = threading.Lock()
        self.discovered_domain: str = ""
        self._domain_lock = threading.Lock()
        self.lockout_threshold: int = -1
        self._policy_lock = threading.Lock()
        self._known_creds: set[str] = set()
        self._creds_lock = threading.Lock()

        self._setup()

    def _setup(self):
        for d in (self.raw_dir, self.loot_dir, self.exploit_dir, self.report_dir,
                  self.bloodhound_dir):
            d.mkdir(parents=True, exist_ok=True)

        if not self.report_path.exists():
            self._write_report_template()

    def next_raw_label(self, label: str) -> str:
        """Return a zero-padded numbered prefix for a raw output file."""
        with self._counter_lock:
            self._raw_counter += 1
            return f"{self._raw_counter:02d}_{label}"

    def set_lockout_threshold(self, n: int):
        """Thread-safe: store the password policy lockout threshold (once)."""
        with self._policy_lock:
            if self.lockout_threshold == -1:
                self.lockout_threshold = n

    def add_cred(self, text: str):
        """Thread-safe append of a discovered credential candidate to loot/creds_found.txt."""
        text = text.strip()
        if not text:
            return
        with self._creds_lock:
            if text in self._known_creds:
                return
            self._known_creds.add(text)
            with open(self.loot_dir / "creds_found.txt", "a") as f:
                f.write(text + "\n")

    def set_discovered_domain(self, domain: str):
        """Thread-safe: store the first domain found during enumeration."""
        with self._domain_lock:
            if not self.discovered_domain and domain:
                self.discovered_domain = domain
                (self.loot_dir / "domain.txt").write_text(domain + "\n")

    def add_valid_cred(self, user: str, password: str, service: str) -> None:
        """Thread-safe: record a confirmed credential pair with the service it was validated against."""
        entry = f"{user}:{password}  [{service}]"
        with self._creds_lock:
            if entry not in self._known_creds:
                self._known_creds.add(entry)
                with (self.loot_dir / "valid_creds.txt").open("a") as fh:
                    fh.write(entry + "\n")

    def add_user(self, username: str):
        """Thread-safe append of a discovered username to loot/users.txt (deduped)."""
        username = username.strip()
        if not username:
            return
        with self._users_lock:
            if username in self._known_users:
                return
            self._known_users.add(username)
            with open(self.loot_dir / "users.txt", "a") as f:
                f.write(username + "\n")

    def _write_report_template(self):
        domain_line = f"**Domain:** {self.domain}\n" if self.domain else ""
        self.report_path.write_text(
            f"# {self.name} — {self.ip}\n\n"
            f"**Date:** {date.today()}\n"
            f"**Target:** {self.ip}\n"
            f"{domain_line}"
            f"**Status:** In Progress\n\n"
            "---\n\n"
            "## Foothold\n\n"
            "## Privilege Escalation\n\n"
            "## Flags\n\n"
            "- User:\n"
            "- Root:\n\n"
            "## Notes\n\n"
        )
