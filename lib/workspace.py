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

        self._raw_counter = 0
        self._counter_lock = threading.Lock()
        self._known_users: set[str] = set()
        self._users_lock = threading.Lock()

        self._setup()

    def _setup(self):
        for d in (self.raw_dir, self.loot_dir, self.exploit_dir, self.report_dir):
            d.mkdir(parents=True, exist_ok=True)

        if not self.report_path.exists():
            self._write_report_template()

    def next_raw_label(self, label: str) -> str:
        """Return a zero-padded numbered prefix for a raw output file."""
        with self._counter_lock:
            self._raw_counter += 1
            return f"{self._raw_counter:02d}_{label}"

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
