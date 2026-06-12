"""
The reified capability model.

An `Action` is a single thing the engine can do (run a tool, probe a service,
drop into a shell). It carries everything the planner needs to decide *whether*
and *how loud* it is, without running anything:

  - `tier`        — how noisy/risky it is on the noise ladder
  - `footprint`   — what evidence it leaves (event IDs / logs / network signature)
  - `gate`        — is it available given the current facts?
  - `requires`    — human-labelled inputs, used to render the greyed-out reason
  - `handler`     — the actual work (wraps an existing enum/attack function)

Keeping all of this as data (not control flow) is what lets the console show
"available / dormant / exhausted", explain *why*, and let the operator steer.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable, Optional

if TYPE_CHECKING:
    from lib.findings import ServiceBuffer
    from lib.runner import Runner

    from lib.engine.facts import FactStore


class Tier(enum.IntEnum):
    """The noise ladder. Ordered so `tier <= posture` is a clean comparison."""

    PASSIVE = 0   # no packets to target (workspace/parse/local only)
    GREEN = 1     # discovery + non-intrusive reads (no auth/security events)
    YELLOW = 2    # writes Windows Security events / obvious auth traffic
    RED = 3       # destructive / exploit-grade (locked unless explicitly armed)

    @property
    def label(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Footprint:
    """What an action leaves behind. Shown on every level, minimal and neutral."""

    summary: str = ""                          # one-line operator-facing note
    windows_events: tuple[str, ...] = ()       # e.g. ("4769",) Kerberoast TGS
    linux_logs: tuple[str, ...] = ()           # e.g. ("auth.log", "wtmp")
    network: str = ""                          # e.g. "SYN sweep — IDS port-scan signature"

    def is_empty(self) -> bool:
        return not (self.summary or self.windows_events or self.linux_logs or self.network)


@dataclass(frozen=True)
class Requirement:
    """A named fact an action needs, with a human label for the greyed-out reason."""

    key: str        # fact key checked via FactStore.has(key), e.g. "domain"
    label: str      # human-readable, e.g. "a domain" / "a valid credential"


@dataclass
class ActionContext:
    """Everything a handler needs; built fresh by the scheduler per dispatch."""

    ip: str
    domain: Optional[str]
    runner: "Runner"
    facts: "FactStore"
    findings: "ServiceBuffer"           # per-action buffer (never the shared Findings)
    available: set[str] = field(default_factory=set)   # installed tool names
    target_port: Optional[int] = None   # for per-port instances
    args: dict = field(default_factory=dict)


@dataclass
class ActionResult:
    ok: bool = True
    summary: str = ""
    discoveries: list = field(default_factory=list)


def _always_available(_facts: "FactStore") -> bool:
    return True


@dataclass
class Action:
    """A reified capability. Pure config — runtime state (tried/exhausted) lives
    in the scheduler, never here, so one Action object is safe to share."""

    name: str
    tier: Tier
    handler: Callable[["ActionContext"], "ActionResult"]
    # Path the action belongs to — the planner/UI present work *by path* (e.g.
    # "discovery", "smb", "ldap", "kerberos", "creds", "ad", "access"), so opening
    # a service lights up its branch and you step through that methodology.
    group: str = "general"
    order: int = 0                       # sort within the group
    footprint: Footprint = field(default_factory=Footprint)
    gate: Callable[["FactStore"], bool] = _always_available
    requires: tuple[Requirement, ...] = ()
    # For per-target fan-out (e.g. one version-detect per open port): returns a
    # list of arg dicts, one dispatched instance each. None = single instance.
    instances: Optional[Callable[["FactStore"], list[dict]]] = None
    deps: tuple[str, ...] = ()           # required tool names (checked vs available set)
    supersedes: tuple[str, ...] = ()     # skip these once this one has run
    # ProtoStatus values of this action's `group` that send it dormant (e.g. an
    # anonymous probe is pointless once the branch is ANON_DENIED) until a new
    # fact or an operator `recheck` clears the status. Kept as a plain tuple to
    # avoid an action→facts import; compared by identity against facts.proto_status.
    suppressed_by: tuple = ()
    # When True, the action is only ever dispatched by an explicit `run <action>`
    # — never swept up by run-all / run <group> / the dial. For deliberate,
    # operator-initiated steps (e.g. dropping a shell) that shouldn't fire as a
    # side effect of a bulk run.
    manual_only: bool = False
    # Red pre-flight: (ok, message). False aborts before the action runs.
    precondition: Optional[Callable[["ActionContext"], tuple[bool, str]]] = None

    def is_available(self, facts: "FactStore") -> bool:
        """Authoritative availability: the gate decides. `requires` is only for
        rendering *why* something is dormant."""
        return bool(self.gate(facts))

    def missing_requirements(self, facts: "FactStore") -> list[Requirement]:
        """The declared inputs not yet satisfied — drives the greyed-out reason.
        Uses duck-typed `facts.has(key)` so it is testable without a real store."""
        return [r for r in self.requires if not facts.has(r.key)]
