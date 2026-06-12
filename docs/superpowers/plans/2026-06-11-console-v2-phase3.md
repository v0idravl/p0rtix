# Console v2 — Phase 3: granular, path-stepping actions

> **For agentic workers:** implement slice-by-slice, lowest-risk first. Each slice
> is independently shippable and live-validated against HTB Forest before the
> next. Steps use checkbox (`- [ ]`) syntax for tracking.

**Origin:** operator feedback from driving the v2 dashboard on Forest. The notes
all converge on one move — **decompose the monolithic module-actions into
granular, per-protocol, path-stepping actions over the fact store** — which is
the doctrine's own "decision-driven, not fan-out-everything" planner. Phase 2's
`ad.authenticated_core` / `creds.spray` were scaffolding to validate the chain;
Phase 3 makes them real.

**Doctrine note (deliberate change):** the operator opted to add an **opt-in
interactive shell launcher** once access is confirmed. This is a bounded
amendment to "standalone recon, not C2": p0rtix may *hand off into* an
interactive `evil-winrm`/`psexec` session, but still does **not** implant, task,
or persist — no C2 framework. CLAUDE.md's doctrine gets a one-paragraph amendment
(Slice 6).

---

## Design principles

1. **One action = one decision.** Every action is a single, individually-runnable
   step a human would choose. No action runs a battery. Convenience "run the
   whole group" is a UI affordance (run-all within a group), not a mega-action.
2. **Actions belong to a path.** Each `Action` gains a `group` (e.g. `discovery`,
   `smb`, `ldap`, `kerberos`, `creds`, `ad`, `access`). The UI and planner present
   work *by path*, so "LDAP is open" lights up the LDAP path and you step through
   its methodology.
3. **Per-protocol status drives dormancy.** A branch that confirms failure
   (`ANON_DENIED`) goes dormant and is **not re-offered** until a new fact unlocks
   it (a cred, a domain). Status is first-class in availability, with a manual
   override to re-arm.
4. **Coverage is remembered.** Discovery tracks which ports it has scanned;
   higher tiers scan only the delta. Nothing re-runs needlessly.

---

## Data-model changes (`lib/engine/`)

| Area | Change |
|------|--------|
| `action.py` | Add `group: str` and `order: int` to `Action` (group = path bucket, order = within-group sort). |
| `facts.py` | Add **`scanned_ports`** (set of TCP ports already swept) with `add_scanned_ports()` + `has_scanned()`. Add **per-hash crack state**: track `(kind, cracked: bool)` so the UI can show uncracked→crack / cracked→plaintext; expose in `snapshot()` as `hashes: [{kind, cracked, plaintext?}]`. |
| `facts.py` | `proto_status` already exists; make it **load-bearing** for availability. |
| `registry.py` | `available()`/`dormant()`/`why()` consult `proto_status`: an action whose proto is `ANON_DENIED`/`NEEDS_CREDS` with its unlock-fact absent is **dormant ("needs a credential")**, not available. Add `groups()` → ordered `{group: [actions]}` for the UI. Add `blocked_by_status` reason in `why`. |
| `scheduler.py` | `recheck(proto)` override to clear a dormant status and re-arm a branch (operator override). Already has `recheck_users`; generalise. |

---

## Action catalogue redesign

**Decompose** (delete the monoliths once parity is reached):

| Old (monolith) | New granular actions (group) |
|----------------|------------------------------|
| `ad.authenticated_core` | `ldap.domaindump` · `kerberos.kerberoast` · `bloodhound.collect` · `ad.writable_objects` · `ad.laps_gmsa` · `secretsdump` (gated on admin) — all group `ad`/`ldap`/`kerberos`, gated `valid_cred`+`domain` |
| `creds.spray` (only option) | `creds.test` (try known user:pass pairs as-is — *verify access*, no fan-out) **and** `creds.spray` (deliberately fan one password across all users) — group `creds` |
| `discovery.tcp_ports` (full only) | `discovery.tcp_top100` (quiet) · `discovery.tcp_top1000` · `discovery.tcp_full` — group `discovery`, each scanning only un-scanned ports |
| `svc.version_detect` (per-port, UI collapses) | keep per-port instances; UI exposes **single-port run** + "all" |

**Port dedup into the planner:** port the classic `_dedup_services()` logic so
sibling ports collapse to the real enum port (445⊃139, 389⊃3268/636) — no useless
duplicate per-port sections. Dedup happens when ports/services become facts.

---

## UI redesign (`lib/engine/console.py`)

- **Actions list grouped by path**, not by available/dormant/exhausted. Each group
  is a header (`▸ LDAP   [anon_denied]`) followed by its actions; per-row glyph
  shows state (`●` available / `○` dormant+reason / `✓` done). The per-proto
  status badge sits on the group header. This is the "step into the path" view.
- **State pane = `status` summary**: target · domain · **N ports known** · posture
  · one-line loot (`users N · creds C/V · hashes U uncracked/K cracked`). Trim the
  fuller breakdown.
- **Hashes by crack-state** in state + a `hashes` view: `uncracked (→ run
  crack.hashes)` vs `cracked: user:plaintext`. Type (asrep/kerberoast/ntlm)
  demoted to a tag.
- **version_detect**: allow `run svc.version_detect <port>` and a per-port pick in
  the list (expand the row), keeping "run all".

---

## Access + shell (Slice 6 — doctrine amendment)

- `creds.test` (group `access`): for each known valid/candidate cred, verify
  access per open service (SMB/WinRM/RDP/MSSQL) via a single `nxc` check — reports
  `[+]` / `Pwn3d!` and records `valid_cred`/`admin_cred`. *Verification, not spray.*
- **Surface the handoff command** always (export boundary): e.g.
  `evil-winrm -i <ip> -u <u> -p <p>`, `impacket-psexec …`.
- **`access.shell` (opt-in)**: launches the interactive session
  (`evil-winrm`/`psexec`) in the operator's terminal. Tier **RED** (armed only);
  suspends the TUI, hands the tty to the child, resumes on exit. p0rtix records
  that a shell was opened but does **not** drive it.
- CLAUDE.md doctrine amendment: add that an *opt-in, operator-initiated
  interactive shell handoff* is in scope, while automated post-ex tasking / C2
  remains out.

---

## Sliced rollout

### Slice 1 — path grouping + state-pane summary (UI-only, low risk) ✅
- [x] Add `group`/`order` to `Action`; tag existing actions.
- [x] `registry.grouped()`; dashboard renders grouped sections with state glyphs
      (available `●` / blocked `◐` / dormant `○`+reason / exhausted `✓`), proto
      status badge on the group header.
- [x] State pane trimmed to the `status` summary (target/domain/#ports/loot/
      lockout/actions). Hashes-by-crack-state deferred to Slice 5 (needs the fact
      model); shown as a kind list for now.
- [x] Pilot + registry tests: grouped ordering/state, grouped rendering,
      state-summary content. (94 pass)

### Slice 2 — decompose the monoliths + `creds.test` ✅
- [x] Extracted `_ad_ldapdomaindump` / `_ad_kerberoast` / `_ad_bloodhound` from
      `_ad_core` (classic mode unchanged — it now calls them). Granular engine
      actions `ldap.domaindump` / `kerberos.kerberoast` / `bloodhound.collect` /
      `ad.writable_objects` replace the `ad.authenticated_core` monolith.
- [x] Added `creds.test` (verify known pair as-is + emit handoff command) vs
      `creds.spray` (deliberate fan-out). New `cred_pair` fact; crack records the
      cracked principal so it's testable, not just sprayable.
- [x] Monolith action removed; classic `_ad_core` retains ADCS/shadow/secretsdump
      (exploitation-leaning steps deferred to the access/RED slice).
- [x] Tests: granular gating, creds.test verify, crack→cred_pair. Live-validated
      on Forest (each AD step ran independently; creds.test confirmed svc-alfresco
      SMB access + WinRM handoff). 96 pass.

### Slice 3 — per-proto status drives availability
- [ ] `proto_status` consulted in `available`/`dormant`/`why`; dormant-until-fact.
- [ ] `scheduler.recheck(proto)` override + `recheck <proto>` command.
- [ ] Tests: anon-denied LDAP goes dormant, re-arms on a cred.

### Slice 4 — tiered incremental discovery + dedup
- [ ] `scanned_ports` fact; `discovery.tcp_top100/top1000/full` scanning the delta.
- [ ] Port dedup in the planner (sibling-port supersession).
- [ ] `svc.version_detect` single-port run in the UI.
- [ ] Tests: delta-only scanning, dedup, single-port version detect.

### Slice 5 — hash crack-state model
- [ ] Per-hash `(kind, cracked, plaintext)` in facts; crack action updates it.
- [ ] UI: uncracked/cracked grouping; actionable.
- [ ] Tests.

### Slice 6 — access verify + opt-in shell (doctrine amendment)
- [ ] `creds.test` + handoff-command export.
- [ ] `access.shell` RED launcher (tty handoff, TUI suspend/resume).
- [ ] CLAUDE.md doctrine amendment paragraph.
- [ ] Tests: access-test recording; shell launch is gated/armed (mock the spawn).

---

## Testing strategy

Mirror Phase 2: unit/gating tests per action (mocked runner), Textual **Pilot**
tests for UI (grouping, state pane, single-port pick), then live validation on
Forest per slice. The shell launcher is unit-tested with a mocked spawn (never a
real child in CI).
