import socket
import subprocess
import sys
from pathlib import Path

HOSTS_FILE = Path("/etc/hosts")


class HostsManager:
    """Manages /etc/hosts additions for discovered vhosts and domains."""

    def __init__(self):
        # Cache of hostnames we've already added this session so we don't prompt twice
        self._added: set[str] = set()

    def resolves(self, hostname: str) -> bool:
        """Return True if the hostname already resolves (DNS or /etc/hosts)."""
        try:
            socket.gethostbyname(hostname)
            return True
        except OSError:
            return False

    def is_known(self, hostname: str) -> bool:
        """Return True if we've already added this hostname this session."""
        return hostname.lower() in self._added

    def prompt_add(self, ip: str, hostname: str) -> bool:
        """
        Ask the operator whether to add `ip hostname` to /etc/hosts.
        Returns True if the entry was added (or already present), False if skipped.
        """
        hostname = hostname.lower()

        if self.resolves(hostname):
            print(f"    [hosts] {hostname} already resolves — skipping")
            self._added.add(hostname)
            return True

        # Non-interactive run (no TTY): auto-add rather than blocking or skipping.
        # Callers only reach prompt_add after an in-scope check, so adding the
        # discovered domain/vhost is safe and keeps AD tooling's name resolution
        # working in unattended runs.
        if not sys.stdin.isatty():
            print(f"    [hosts] non-interactive — auto-adding {ip} {hostname}")
            return self._write_entry(ip, hostname)

        print(f"\n  [?] Add to /etc/hosts?  {ip}  {hostname}")
        try:
            answer = input("      [Y/n] > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False

        if answer in ("", "y", "yes"):
            return self._write_entry(ip, hostname)
        return False

    def add_silent(self, ip: str, hostname: str) -> bool:
        """Add entry without prompting (used when running fully automated)."""
        hostname = hostname.lower()
        if self.resolves(hostname):
            self._added.add(hostname)
            return True
        return self._write_entry(ip, hostname)

    def _write_entry(self, ip: str, hostname: str) -> bool:
        entry = f"{ip}\t{hostname}\n"
        try:
            # Running as root so we can write directly
            with HOSTS_FILE.open("a") as fh:
                fh.write(entry)
            self._added.add(hostname)
            print(f"    [hosts] Added: {entry.strip()}")
            return True
        except PermissionError:
            # Fallback: try sudo tee
            result = subprocess.run(
                ["tee", "-a", str(HOSTS_FILE)],
                input=entry, text=True, capture_output=True
            )
            if result.returncode == 0:
                self._added.add(hostname)
                print(f"    [hosts] Added via tee: {entry.strip()}")
                return True
            print(f"    [!] Could not write to /etc/hosts: {result.stderr.strip()}")
            return False
