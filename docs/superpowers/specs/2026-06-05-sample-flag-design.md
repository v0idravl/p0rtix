# `--sample` Flag Design

## Overview

Add a `--sample` flag that creates a zip archive of the target's workspace directory at the end of a normal scan run, leaving all files in place.

## Flag

- **Name:** `--sample`
- **Type:** boolean (`store_true`)
- **Location:** `parse_args()` in `p0rtix.py`
- **No short form** (avoids conflicts with existing flags)

## Core Implementation

**Method:** `Workspace.create_sample() -> Path` in `lib/workspace.py`

Placing it on `Workspace` is the right home because it operates entirely on the workspace layout.

### Behaviour

1. Generate output filename: `<ws.name>_<secrets.token_hex(4)>.zip` (e.g. `certified_3f8a1b2c.zip`)
2. Create the zip at `ws.machine_dir / <filename>`
3. Walk `ws.machine_dir` recursively via `zipfile.ZipFile` in write mode
4. Store each file with a path relative to `ws.machine_dir` (so the archive extracts cleanly into a named folder)
5. Skip any files matching `*.zip` already present in `ws.machine_dir` (prevents archiving a previous sample zip into the new one)
6. Return the `Path` of the created zip

### Imports needed

- `import secrets` (stdlib)
- `import zipfile` (stdlib)

## Invocation

Called at the very end of `main()` in `p0rtix.py`, after all scan phases and after `--analyze` (if present), when `args.sample` is True:

```python
if args.sample:
    zip_path = ws.create_sample()
    print(f"[+] Sample zip: {zip_path}")
```

## Output

- Zip file lands in `ws.machine_dir` (e.g. `~/htb/certified/certified_3f8a1b2c.zip`)
- Single print line reports the path on completion
- No entry written to `findings.md` (this is an operator convenience, not a finding)

## Edge Cases

- **Re-runs:** Existing `*.zip` files in the directory are excluded from the new archive. Each run produces a uniquely named zip.
- **Large workspaces:** No size limit; `raw/` directory is included as requested.
- **Failure:** If zip creation fails, log the error and continue — do not abort the run.
