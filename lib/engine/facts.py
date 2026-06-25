"""
The event-emitting fact store.

`Workspace` is already a thread-safe store of everything learned during a
campaign (users, creds, domain, lockout, hostnames) that writes the loot files.
`FactStore` subclasses it and adds the one thing the planner needs: **events**.
Every mutator emits a `FactEvent` *when it actually changes state*, so the
scheduler can re-evaluate which actions are now available ("unlock on new fact").

It also tracks open ports / services / per-protocol status, and answers
`has(key)` so an Action's `requires` can be checked for the greyed-out display.

Concurrency rule (load-bearing): listeners are invoked **outside** the inherited
field locks (emit-after-commit). A mutator commits under its lock, releases, then
emits — so a listener is free to call back into the store without deadlocking.
"""
from __future__ import annotations

import enum
import threading
from dataclasses import dataclass
from typing import Callable

from lib.models import Service
from lib.wordlists import Breadth
from lib.workspace import Workspace


class ProtoStatus(enum.Enum):
    UNREACHABLE = "unreachable"
    ANON_DENIED = "anon_denied"
    NEEDS_CREDS = "needs_creds"
    IN_PROGRESS = "in_progress"
    EXHAUSTED = "exhausted"


@dataclass(frozen=True)
class FactEvent:
    kind: str            # "user"|"cred"|"valid_cred"|"admin_cred"|"domain"|
                         # "lockout"|"hostname"|"users_complete"|"port_open"|
                         # "service"|"proto_status"
    value: object = None
    source: str = ""     # action name that produced it (for provenance)


Listener = Callable[[FactEvent], None]


class FactStore(Workspace):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._listeners: list[Listener] = []
        self._listener_lock = threading.Lock()
        self._proto_status: dict[str, ProtoStatus] = {}
        self._open_ports: set[tuple[str, int]] = set()   # (proto, port)
        self._scanned_tcp: set[int] = set()              # TCP ports already swept (coverage)
        self._services: list[Service] = []
        self._admin_creds: set[tuple[str, str]] = set()
        self._cred_pairs: set[tuple[str, str]] = set()   # unverified (user, pass) pairs
        # captured hashes keyed by (kind, principal) → {cracked: bool, plaintext}
        self._hashes: dict[tuple[str, str], dict] = {}
        self._engine_lock = threading.Lock()             # guards the new fields above
        # concise→broad effort knob (orthogonal to the noise ladder); drives crack
        # rule depth today, web wordlist breadth next. Default: a sensible middle.
        self.breadth: Breadth = Breadth.STANDARD
        # SMB signing posture: True=required, False=not required (relay target),
        # None=unknown. Surfaced in the handoff so an agent can pick relay targets.
        self._smb_signing_required: bool | None = None
        # detected web technologies/versions, as (port, "tech") — e.g.
        # (80, "HFS 2.3"), (80, "JQuery 1.4.4"). Web enum populates this so the
        # fingerprint is structured (snapshot/handoff), not only in findings_md.
        self._web_tech: set[tuple[int, str]] = set()

    # ── event plumbing ────────────────────────────────────────────────────────
    def subscribe(self, fn: Listener) -> None:
        with self._listener_lock:
            self._listeners.append(fn)

    def _emit(self, ev: FactEvent) -> None:
        # Copy listeners under the lock, then call them holding NO fact lock so a
        # listener can safely re-enter the store.
        with self._listener_lock:
            listeners = list(self._listeners)
        for fn in listeners:
            fn(ev)

    # ── overridden Workspace mutators (emit only on real change) ───────────────
    def add_user(self, username: str, *, authoritative: bool = False) -> None:
        name = username.strip()
        is_new = bool(name) and name not in self._known_users
        had_users = bool(self._known_users)
        super().add_user(username, authoritative=authoritative)
        if is_new:
            self._emit(FactEvent("user", name))
            if not had_users:
                self._emit(FactEvent("users", True))   # first user — "users" fact flips

    def add_cred(self, text: str) -> None:
        candidate = text.strip()
        is_new = bool(candidate) and candidate not in self._known_creds
        super().add_cred(text)
        if is_new:
            self._emit(FactEvent("cred", candidate))

    def add_valid_cred(self, user: str, password: str, service: str) -> None:
        key = (user, password)
        is_new = key not in self._known_valid
        super().add_valid_cred(user, password, service)
        # A confirmed credential teaches two more facts: its account is a real
        # user (→ the user list, for roasting/enum) and its password is a spray
        # candidate (→ against every other user). Both are deduped.
        if user and not user.endswith("$"):
            self.add_user(user, authoritative=True)
        if password:
            self.add_cred(password)
        if is_new:
            self._emit(FactEvent("valid_cred", key))

    def add_admin_cred(self, user: str, password: str) -> None:
        """Record a credential confirmed to have admin/privileged access. Unlocks
        admin-gated actions (shells via psexec/wmiexec, secretsdump)."""
        key = (user, password)
        with self._engine_lock:
            is_new = key not in self._admin_creds
            self._admin_creds.add(key)
        # also record it as a valid cred (emits its own event if new)
        self.add_valid_cred(user, password, "admin")
        if is_new:
            self._emit(FactEvent("admin_cred", key))

    def set_discovered_domain(self, domain: str) -> None:
        was_empty = not self.discovered_domain
        super().set_discovered_domain(domain)
        if was_empty and self.discovered_domain:
            self._emit(FactEvent("domain", self.discovered_domain))

    def set_lockout_threshold(self, n: int) -> None:
        was_unknown = self.lockout_threshold == -1
        super().set_lockout_threshold(n)
        if was_unknown and self.lockout_threshold != -1:
            self._emit(FactEvent("lockout", self.lockout_threshold))

    def add_hostname(self, fqdn: str) -> None:
        name = fqdn.strip().lower()
        is_new = bool(name) and name not in self._known_hostnames
        super().add_hostname(fqdn)
        if is_new:
            self._emit(FactEvent("hostname", name))

    def mark_users_complete(self) -> None:
        was_complete = self.users_complete
        super().mark_users_complete()
        if not was_complete and self.users_complete:
            self._emit(FactEvent("users_complete", True))

    # ── new engine facts ──────────────────────────────────────────────────────
    def add_open_port(self, proto: str, port: int) -> None:
        key = (proto, port)
        with self._engine_lock:
            is_new = key not in self._open_ports
            self._open_ports.add(key)
        if is_new:
            self._emit(FactEvent("port_open", key))

    def add_scanned_tcp(self, ports) -> None:
        """Record TCP ports that have been *swept* (open or not), so a broader
        tier scans only the delta. Emits 'scanned' when coverage grows."""
        new = {int(p) for p in ports}
        with self._engine_lock:
            grew = not new <= self._scanned_tcp
            self._scanned_tcp |= new
        if grew:
            self._emit(FactEvent("scanned", ("tcp", sorted(new))))

    def scanned_tcp(self) -> set[int]:
        with self._engine_lock:
            return set(self._scanned_tcp)

    def set_services(self, services: list[Service]) -> None:
        with self._engine_lock:
            self._services = list(services)
            for s in services:
                self._open_ports.add((s.proto, s.port))
        self._emit(FactEvent("service", list(services)))

    def add_services(self, services: list[Service]) -> None:
        """Merge newly version-detected services in (e.g. one port at a time),
        deduped by (proto, port). Emits a single 'service' event for the batch."""
        added = []
        with self._engine_lock:
            existing = {(s.proto, s.port) for s in self._services}
            for s in services:
                if (s.proto, s.port) not in existing:
                    self._services.append(s)
                    existing.add((s.proto, s.port))
                    added.append(s)
                self._open_ports.add((s.proto, s.port))
        if added:
            self._emit(FactEvent("service", added))

    def get_services(self) -> list[Service]:
        with self._engine_lock:
            return list(self._services)

    def add_cred_pair(self, user: str, password: str) -> None:
        """Record an **unverified** (user, password) pair — e.g. a cracked hash's
        principal, or one the operator wants to test. Distinct from a valid_cred
        (confirmed) and a bare cred candidate (password only). Unlocks
        `creds.test`, which verifies it as that specific pair rather than spraying."""
        key = (user.strip(), password)
        with self._engine_lock:
            is_new = bool(key[0]) and key not in self._cred_pairs and key not in self._known_valid
            if is_new:
                self._cred_pairs.add(key)
        # surface the account as a user and the password as a spray candidate
        if key[0] and not key[0].endswith("$"):
            self.add_user(key[0], authoritative=True)
        self.add_cred(password)
        if is_new:
            self._emit(FactEvent("cred_pair", key))

    def add_hash(self, kind: str, principal: str = "", *,
                 cracked: bool = False, plaintext: str | None = None) -> None:
        """Record a captured hash of `kind` (asrep/kerberoast/ntlm) for `principal`.
        Unlocks the offline crack action while any hash is uncracked. Type is
        secondary — the actionable axis is cracked vs uncracked."""
        kind = kind.strip().lower()
        if not kind:
            return
        key = (kind, principal.strip())
        with self._engine_lock:
            rec = self._hashes.get(key)
            changed = rec is None or (cracked and not rec["cracked"])
            if rec is None:
                self._hashes[key] = {"cracked": cracked, "plaintext": plaintext}
            elif cracked and not rec["cracked"]:
                rec.update(cracked=True, plaintext=plaintext)
        if changed:
            self._emit(FactEvent("hash", key))

    def mark_hash_cracked(self, principal: str, plaintext: str) -> None:
        """Flip every captured hash for `principal` to cracked with its plaintext."""
        principal = principal.strip()
        changed = False
        with self._engine_lock:
            for (kind, prin), rec in self._hashes.items():
                if prin == principal and not rec["cracked"]:
                    rec.update(cracked=True, plaintext=plaintext)
                    changed = True
        if changed:
            self._emit(FactEvent("hash", ("cracked", principal)))

    def set_smb_signing(self, required: bool) -> None:
        """Record whether SMB signing is required. `required=False` marks this host
        as an NTLM-relay target. Emits so a planner can react."""
        with self._engine_lock:
            changed = self._smb_signing_required is not required
            self._smb_signing_required = required
        if changed:
            self._emit(FactEvent("smb_signing", required))

    def add_web_tech(self, port: int, tech: str) -> None:
        """Record a detected web technology/version for a port (e.g.
        (80, "HFS 2.3")). Deduped; emits so the fingerprint rides along in the
        snapshot / handoff as structured fact, not only in findings_md."""
        tech = (tech or "").strip()
        if not tech:
            return
        key = (int(port), tech)
        with self._engine_lock:
            is_new = key not in self._web_tech
            self._web_tech.add(key)
        if is_new:
            self._emit(FactEvent("web_tech", key))

    def set_proto_status(self, proto: str, status: ProtoStatus) -> None:
        with self._engine_lock:
            changed = self._proto_status.get(proto) is not status
            self._proto_status[proto] = status
        if changed:
            self._emit(FactEvent("proto_status", (proto, status)))

    def proto_status(self, proto: str) -> ProtoStatus | None:
        with self._engine_lock:
            return self._proto_status.get(proto)

    def clear_proto_status(self, proto: str) -> None:
        """Forget a protocol's status (operator `recheck` override) so a dormant
        branch can be re-armed."""
        with self._engine_lock:
            existed = self._proto_status.pop(proto, None) is not None
        if existed:
            self._emit(FactEvent("proto_status", (proto, None)))

    # ── queries ───────────────────────────────────────────────────────────────
    def has(self, key: str) -> bool:
        """Answer a named-fact check used by Action gates / `requires`.

        Keys: "domain", "users", "valid_cred", "admin_cred", "lockout_known",
        and port checks like "tcp/445" / "udp/161"."""
        if key == "domain":
            return bool(self.discovered_domain)
        if key == "users":
            return bool(self._known_users)
        if key == "cred":               # a candidate password (cracked/leaked), unvalidated
            return bool(self._known_creds)
        if key == "cred_pair":          # an unverified (user, pass) pair to test
            with self._engine_lock:
                return bool(self._cred_pairs)
        if key == "valid_cred":
            return bool(self._known_valid)
        if key == "admin_cred":
            with self._engine_lock:
                return bool(self._admin_creds)
        if key == "lockout_known":
            return self.lockout_threshold != -1
        if key == "hash":
            with self._engine_lock:
                return bool(self._hashes)
        if key == "hash:uncracked":
            with self._engine_lock:
                return any(not r["cracked"] for r in self._hashes.values())
        if key.startswith("hash:"):
            want = key.split(":", 1)[1]
            with self._engine_lock:
                return any(kind == want for (kind, _prin) in self._hashes)
        if "/" in key:
            proto, _, port = key.partition("/")
            try:
                return (proto, int(port)) in self._open_ports
            except ValueError:
                return False
        return False

    def snapshot(self) -> dict:
        """Read-only view for the dashboard. Cheap copies, no locks held by caller."""
        with self._engine_lock:
            open_ports = sorted(self._open_ports, key=lambda x: (x[0], x[1]))
            proto_status = {k: v.value for k, v in self._proto_status.items()}
            admin = len(self._admin_creds)
            admin_pairs = sorted(self._admin_creds)
            cred_pairs = sorted(self._cred_pairs)
            hashes = [
                {"kind": kind, "principal": prin,
                 "cracked": rec["cracked"], "plaintext": rec["plaintext"]}
                for (kind, prin), rec in sorted(self._hashes.items())
            ]
            scanned_tcp = len(self._scanned_tcp)
            smb_signing = self._smb_signing_required
            web_tech = sorted(self._web_tech)
            services = [
                {"port": s.port, "proto": s.proto, "name": s.name,
                 "version": s.version, "is_web": s.is_web, "scheme": s.scheme}
                for s in sorted(self._services, key=lambda s: (s.proto, s.port))
            ]
        return {
            "ip": self.ip,
            "domain": self.discovered_domain or self.domain or "",
            "users": sorted(self._known_users),
            "creds": sorted(self._known_creds),
            "valid_creds": sorted(self._known_valid),
            "admin_creds": admin,
            "admin_pairs": admin_pairs,
            "hostnames": sorted(self._known_hostnames),
            "lockout": self.lockout_threshold,
            "users_complete": self.users_complete,
            "open_ports": open_ports,
            "proto_status": proto_status,
            "hashes": hashes,
            "cred_pairs": cred_pairs,
            "scanned_tcp": scanned_tcp,
            "smb_signing_required": smb_signing,
            "web_tech": [{"port": p, "tech": t} for (p, t) in web_tech],
            "services": services,
        }

    # ── reload from disk (pick up external edits to loot/*.txt) ────────────────
    def reload(self) -> int:
        """Re-read the loot files and feed any new entries through the mutators
        (which emit for genuinely-new facts). Returns the count of new facts.
        Lets the operator edit loot/users.txt etc. and `reload` to refresh."""
        before = len(self._known_users) + len(self._known_creds) + len(self._known_valid)

        users_path = self.loot_dir / "users.txt"
        if users_path.exists():
            for line in users_path.read_text().splitlines():
                if line.strip():
                    self.add_user(line.strip())

        creds_path = self.loot_dir / "creds_found.txt"
        if creds_path.exists():
            for line in creds_path.read_text().splitlines():
                if line.strip():
                    self.add_cred(line.strip())

        valid_path = self.loot_dir / "valid_creds.txt"
        if valid_path.exists():
            import re
            for line in valid_path.read_text().splitlines():
                line = re.sub(r"\s*\[[^\]]*\]\s*$", "", line.strip())
                if ":" in line:
                    u, p = line.split(":", 1)
                    self.add_valid_cred(u.strip(), p.strip(), "reload")

        domain_path = self.loot_dir / "domain.txt"
        if domain_path.exists():
            saved = domain_path.read_text().strip()
            if saved:
                self.set_discovered_domain(saved)

        after = len(self._known_users) + len(self._known_creds) + len(self._known_valid)
        return after - before
