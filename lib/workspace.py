import re
import secrets
import threading
import zipfile
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

    def __init__(self, ip: str, domain: str | None, name: str | None, workspace: str, mode: str = "scan"):
        self.ip = ip
        self.domain = domain
        self.deep = False  # set by the orchestrator from --deep; gates high-noise checks

        slug = name if name else (domain if domain else ip)
        self.name = _slugify(slug)

        self.machine_dir = Path(workspace).resolve() / self.name
        prefix = f"{mode}_" if mode != "scan" else ""
        self.raw_dir = self.machine_dir / f"{prefix}raw"
        self.loot_dir = self.machine_dir / "loot"
        self.exploit_dir = self.machine_dir / "exploit"
        self.report_dir = self.machine_dir / "report"
        self.findings_path = self.machine_dir / f"{prefix}findings.md"
        self.report_path = self.report_dir / "report.md"
        self.bloodhound_dir = self.loot_dir / "bloodhound"
        self.log_dir = self.machine_dir / "logs"

        self._raw_counter = 0
        self._counter_lock = threading.Lock()
        self._known_users: set[str] = set()
        self._dc_sourced_users: set[str] = set()
        self.users_complete: bool = False
        self._users_lock = threading.Lock()
        self._known_hostnames: set[str] = set()
        self._hostnames_lock = threading.Lock()
        self.discovered_domain: str = ""
        self._domain_lock = threading.Lock()
        self.lockout_threshold: int = -1
        self._policy_lock = threading.Lock()
        self._known_creds: set[str] = set()
        self._known_valid: set[tuple[str, str]] = set()
        self._creds_lock = threading.Lock()
        self._sprayed: set[tuple[str, str]] = set()
        self._spray_lock = threading.Lock()

        self._setup()

    def _setup(self):
        for d in (self.raw_dir, self.loot_dir, self.exploit_dir, self.report_dir,
                  self.bloodhound_dir, self.log_dir):
            d.mkdir(parents=True, exist_ok=True)

        if not self.report_path.exists():
            self._write_report_template()

        # Pre-populate in-memory sets from any prior run so re-runs don't re-append duplicates
        users_path = self.loot_dir / "users.txt"
        if users_path.exists():
            self._known_users = {u.strip() for u in users_path.read_text().splitlines() if u.strip()}
        creds_path = self.loot_dir / "creds_found.txt"
        if creds_path.exists():
            self._known_creds = {c.strip() for c in creds_path.read_text().splitlines() if c.strip()}
        valid_path = self.loot_dir / "valid_creds.txt"
        if valid_path.exists():
            for line in valid_path.read_text().splitlines():
                line = re.sub(r"\s*\[[^\]]*\]\s*$", "", line.strip())
                if ":" in line:
                    u, p = line.split(":", 1)
                    u = u.strip()
                    if u:  # skip empty-username entries (must-change artifacts)
                        self._known_valid.add((u, p.strip()))
        # Restore discovered domain from prior scan so creds/follow-up runs inherit it
        domain_path = self.loot_dir / "domain.txt"
        if domain_path.exists():
            saved = domain_path.read_text().strip()
            if saved:
                self.discovered_domain = saved

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
        """
        Thread-safe: record a confirmed credential pair, deduped by the logical
        (user, password) so the same cred validated by multiple code paths /
        services produces a single line (tagged with the first service seen).
        """
        key = (user, password)
        entry = f"{user}:{password}  [{service}]"
        with self._creds_lock:
            if key in self._known_valid:
                return
            self._known_valid.add(key)
            with (self.loot_dir / "valid_creds.txt").open("a") as fh:
                fh.write(entry + "\n")

    def append_hash_file(self, filename: str, new_hashes: list[str]) -> int:
        """Append unique hashes to loot/<filename>. Returns count of newly added hashes."""
        path = self.loot_dir / filename
        existing: set[str] = set()
        if path.exists():
            existing = set(path.read_text().splitlines())
        unique = [h for h in new_hashes if h.strip() and h.strip() not in existing]
        if unique:
            with path.open("a") as fh:
                fh.write("\n".join(unique) + "\n")
        return len(unique)

    def unsprayed_users(self, users: list[str], password: str) -> list[str]:
        """
        Return the subset of `users` not yet sprayed with `password`, recording
        them as sprayed. Prevents the escalation loop from re-testing the same
        (user, password) across rounds — fewer logins, less noise.
        """
        with self._spray_lock:
            out = []
            for u in users:
                key = (u.strip().lower(), password)
                if key not in self._sprayed:
                    self._sprayed.add(key)
                    out.append(u)
            return out

    @staticmethod
    def _krb_principal(h: str) -> str:
        """Account name embedded in an AS-REP/TGS hashcat hash (lowercased)."""
        m = re.search(r"\$krb5asrep\$\d+\$([^@:]+)@", h)
        if m:
            return m.group(1).lower()
        m = re.search(r"\$krb5tgs\$\d+\$\*([^$*]+)\$", h)
        if m:
            return m.group(1).lower()
        return h.strip().lower()

    def append_krb_hashes(self, filename: str, new_hashes: list[str]) -> int:
        """
        Append Kerberos hashes (AS-REP / Kerberoast) deduped by ACCOUNT, not by
        full string. GetNPUsers/GetUserSPNs emit a fresh ciphertext on every run,
        so the same account yields a different hash string each time — keying on
        the embedded principal keeps one hash per account. Returns count added.
        """
        path = self.loot_dir / filename
        seen = set()
        if path.exists():
            seen = {self._krb_principal(l) for l in path.read_text().splitlines() if l.strip()}
        added = 0
        with path.open("a") as fh:
            for h in new_hashes:
                h = h.strip()
                if not h:
                    continue
                acct = self._krb_principal(h)
                if acct in seen:
                    continue
                seen.add(acct)
                fh.write(h + "\n")
                added += 1
        return added

    def add_hostname(self, fqdn: str):
        """Thread-safe append of a discovered DC/host FQDN to loot/hostnames.txt (deduped)."""
        fqdn = fqdn.strip().lower()
        if not fqdn:
            return
        with self._hostnames_lock:
            if fqdn in self._known_hostnames:
                return
            self._known_hostnames.add(fqdn)
            with open(self.loot_dir / "hostnames.txt", "a") as f:
                f.write(fqdn + "\n")

    def add_user(self, username: str, *, authoritative: bool = False):
        """Thread-safe append of a discovered username to loot/users.txt (deduped).

        authoritative=True marks the name as confirmed-real — it came from
        enumerating actual accounts (LDAP directory, RID cycling, SMB --users,
        enum4linux, SNMP) rather than a guessed/seeded wordlist. Confirmed names
        need no kerbrute validation, so they are excluded from unverified_users().
        """
        username = username.strip()
        if not username:
            return
        with self._users_lock:
            if authoritative:
                self._dc_sourced_users.add(username)
            if username in self._known_users:
                return
            self._known_users.add(username)
            with open(self.loot_dir / "users.txt", "a") as f:
                f.write(username + "\n")

    def mark_users_complete(self):
        """Signal that an authoritative full-directory enumeration succeeded, so
        loot/users.txt is the complete domain roster rather than a partial guess.
        Lets the post-domain phase skip redundant user re-collection/validation.
        Idempotent; first write wins."""
        with self._users_lock:
            self.users_complete = True

    def unverified_users(self) -> list[str]:
        """Users whose existence is NOT confirmed by an authoritative enumeration
        (e.g. seeded via --users or OSINT). The only names worth validating with
        kerbrute — DC-sourced names are valid by definition."""
        with self._users_lock:
            return sorted(self._known_users - self._dc_sourced_users)

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

    def create_sample(self) -> Path:
        """Zip the entire machine directory into a uniquely-named archive inside it."""
        zip_name = f"{self.name}_{secrets.token_hex(4)}.zip"
        zip_path = self.machine_dir / zip_name
        try:
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for file in self.machine_dir.rglob("*"):
                    if not file.is_file():
                        continue
                    if file.suffix == ".zip":
                        continue
                    zf.write(file, file.relative_to(self.machine_dir))
        except Exception as exc:
            zip_path.unlink(missing_ok=True)
            raise RuntimeError(f"create_sample failed: {exc}") from exc
        return zip_path
