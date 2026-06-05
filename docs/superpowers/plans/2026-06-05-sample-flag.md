# `--sample` Flag Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `--sample` flag that zips the target's workspace directory at the end of a scan run and places the archive inside that directory.

**Architecture:** `Workspace.create_sample()` handles the zip logic in `lib/workspace.py`; `p0rtix.py` adds the CLI flag and calls the method just before `_chown()` so the zip file gets chowned with everything else.

**Tech Stack:** Python stdlib — `zipfile`, `secrets`, `pathlib`

---

## File Map

| File | Change |
|------|--------|
| `lib/workspace.py` | Add `import secrets, zipfile`; add `create_sample()` method |
| `p0rtix.py` | Add `--sample` argument; call `ws.create_sample()` in wrap-up block |

---

### Task 1: Add `create_sample()` to `Workspace`

**Files:**
- Modify: `lib/workspace.py:1-6` (imports)
- Modify: `lib/workspace.py` (add method at end of class)

- [ ] **Step 1: Add stdlib imports**

In `lib/workspace.py`, update the import block at the top from:

```python
import re
import threading
from datetime import date
from pathlib import Path
```

to:

```python
import re
import secrets
import threading
import zipfile
from datetime import date
from pathlib import Path
```

- [ ] **Step 2: Add `create_sample()` at the end of the `Workspace` class**

Locate the last method in the class (scroll to the bottom of `lib/workspace.py`) and append:

```python
def create_sample(self) -> Path:
    """Zip the entire machine directory into a uniquely-named archive inside it."""
    zip_name = f"{self.name}_{secrets.token_hex(4)}.zip"
    zip_path = self.machine_dir / zip_name
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in self.machine_dir.rglob("*"):
                if file.suffix == ".zip":
                    continue
                if file.is_file():
                    zf.write(file, file.relative_to(self.machine_dir))
    except Exception as exc:
        zip_path.unlink(missing_ok=True)
        raise RuntimeError(f"create_sample failed: {exc}") from exc
    return zip_path
```

- [ ] **Step 3: Smoke-test the method manually**

From the repo root, run:

```bash
python3 - <<'EOF'
from lib.workspace import Workspace
ws = Workspace("1.2.3.4", None, "testmachine", "/tmp")
ws.machine_dir.joinpath("findings.md").write_text("test")
p = ws.create_sample()
print("zip created:", p)
import zipfile
with zipfile.ZipFile(p) as zf:
    print("contents:", zf.namelist())
import shutil; shutil.rmtree(ws.machine_dir)
EOF
```

Expected output (random hex will differ):

```
zip created: /tmp/testmachine/testmachine_<hex8>.zip
contents: ['findings.md']
```

- [ ] **Step 4: Commit**

```bash
git add lib/workspace.py
git commit -m "feat: add Workspace.create_sample() for --sample zip"
```

---

### Task 2: Wire up the `--sample` flag in `p0rtix.py`

**Files:**
- Modify: `p0rtix.py:80-92` (add arg after `--rescan`)
- Modify: `p0rtix.py:382-393` (insert sample call before `_chown`)

- [ ] **Step 1: Add the flag to `parse_args()`**

In `p0rtix.py`, locate `parse_args()`. After the `--rescan` argument line (~line 82), add:

```python
    p.add_argument("--sample", action="store_true",
                   help="zip the workspace directory at end of scan")
```

- [ ] **Step 2: Call `create_sample()` in the wrap-up block**

In `p0rtix.py`, locate the wrap-up block inside `_scan_target()` (around line 382). It currently reads:

```python
    # ── Wrap up ────────────────────────────────────────────────────────────────
    state.mark_done("complete")
    findings.finalize()
    if args.analyze:
        analyze_findings(ws, ip, domain, model=args.model)

    _chown(ws)
    _print_loot_summary(ws)
```

Add the sample call after `analyze_findings` and **before** `_chown` so the zip file gets chowned along with everything else:

```python
    # ── Wrap up ────────────────────────────────────────────────────────────────
    state.mark_done("complete")
    findings.finalize()
    if args.analyze:
        analyze_findings(ws, ip, domain, model=args.model)

    if args.sample:
        try:
            zip_path = ws.create_sample()
            print(f"[+] Sample    : {zip_path}")
        except RuntimeError as exc:
            print(f"[!] Sample zip failed: {exc}")

    _chown(ws)
    _print_loot_summary(ws)
```

- [ ] **Step 3: Verify the flag appears in help**

```bash
python3 p0rtix.py --help | grep sample
```

Expected:

```
  --sample              zip the workspace directory at end of scan
```

- [ ] **Step 4: Commit**

```bash
git add p0rtix.py
git commit -m "feat: add --sample flag to zip workspace at end of scan"
```
