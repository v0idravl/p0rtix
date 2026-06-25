```text
██████╗  ██████╗ ██████╗ ████████╗██╗██╗  ██╗
██╔══██╗██╔═████╗██╔══██╗╚══██╔══╝██║╚██╗██╔╝
██████╔╝██║██╔██║██████╔╝   ██║   ██║ ╚███╔╝
██╔═══╝ ████╔╝██║██╔══██╗   ██║   ██║ ██╔██╗
██║     ╚██████╔╝██║  ██║   ██║   ██║██╔╝ ██╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝
   scope-aware recon & enumeration · MCP-first (CLI + TUI)
```

![python](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)
![mode](https://img.shields.io/badge/MCP-server-7C3AED)
![platform](https://img.shields.io/badge/platform-Kali%20Linux-557C94?logo=kalilinux&logoColor=white)
![license](https://img.shields.io/badge/license-educational%20%2F%20authorized%20use-3DA639)
![scope](https://img.shields.io/badge/scope-enforced-E03C31)

**An MCP-first, scope-aware recon & enumeration framework for authorized security assessments** —
primarily driven by an AI agent over MCP, and equally runnable standalone (interactive TUI or
headless CLI). p0rtix collects repeatable evidence, keeps raw output intact, and never wanders
outside the agreed scope. It owns the **recon → initial-access leg of the AI-offsec stack**: it
enumerates and *tests* access, then hands off via `export_handoff` to the exploitation/privesc
layer (Metasploit MCP) and on to C2 ([sliver-mcp](https://github.com/v0idravl/sliver-mcp)), with
[dagar-red](https://github.com/v0idravl/dagar-red) supplying the skill/judgment layer across the
chain.

Built around a personal methodology reference ([hakiki](https://github.com/v0idravl/hakiki)) —
port discovery, per-service enumeration, web directory/vhost busting, crawling, and SSL
inspection. Results stream to a single `findings.md` as the scan runs, with every raw tool
output archived separately so nothing is lost.

> ⚠️ **Authorized use only.** Run p0rtix only against systems where you have explicit permission
> and a documented scope. The tool preserves evidence and filters follow-up discovery, but the
> operator remains responsible for rate limits, rules of engagement, and legal authorization.

---

## ⚡ Quick start

```bash
# clone + install
git clone git@github.com:v0idravl/p0rtix.git && cd p0rtix
python3 -m venv venv && ./venv/bin/pip install -e '.[mcp]'

# scan a box (root needed for SYN scans + /etc/hosts writes)
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --workspace ~/htb

# read the results
$EDITOR ~/htb/test.htb/findings.md      # key findings, live-updated
ls     ~/htb/test.htb/raw/              # full tool output, command-headed

# or run it as an MCP server and let an agent drive it
p0rtix-mcp --workspace ~/engagements
```

---

## 🧠 What it does

- **Full TCP SYN scan + top-100 UDP** with automatic confirmation of `open|filtered` ports
- **Service classification** — routes web ports to web enumeration, everything else to per-service handlers
- **Web:** headers, WhatWeb fingerprint, redirect detection, SSL cert SAN extraction, directory bust, vhost bust, crawl (scope-filtered)
- **Services:** FTP, SSH, SMTP, DNS, RPC/NFS, MSRPC, SMB, SNMP, LDAP, Rsync, MSSQL, Oracle, MySQL, RDP, PostgreSQL, WinRM, Redis, MongoDB
- **Creds mode** (`--mode creds` / `--mode scan,creds`) — authenticated AD enumeration in authorized environments: SMB validation, ldapdomaindump, Kerberoasting, AS-REP roasting, BloodHound collection, ADCS template review, evidence capture
- **MCP server** (`--mode mcp` / `p0rtix-mcp`) — drives the recon engine from an AI agent over the [Model Context Protocol](https://modelcontextprotocol.io); quiet/surgical by default via the noise ladder, with `export_handoff` emitting a structured inventory for an exploitation agent. Recon only — tests access and runs single commands non-interactively, never an interactive shell
- **Reactive follow-up** — discovered vhosts and SSL SANs prompt for `/etc/hosts` addition, then get fully enumerated
- **Scope enforcement** — crawl and follow-up never touch out-of-scope hosts
- Single `findings.md` updated in real time; `raw/` directory with every tool's full output, each file headed by the exact command
- Prompts before installing missing tools via `apt`, `pip`/`pipx`, `go install`, or selected GitHub release downloads

### What this demonstrates

Practical Python orchestration around common pentest tools without hiding raw evidence ·
scope-aware follow-up logic for crawled URLs, vhosts, SSL SANs, and resolved hostnames ·
incremental findings generation suitable for handoff · resume/reuse of prior scan data to
avoid repeat network activity · credentialed AD workflow with loot separated from reporting.

---

## 🧩 Part of the AI-offsec stack

p0rtix is the **recon → initial-access leg** of the stack that drives a full authorized
engagement under operator control. It also **bootstraps the engagement**: it initializes the
workspace and evidence layout (`findings.md`, `raw/`, `loot/`, `report/`, `exploit/`) and seeds
working artifacts like `loot/users.txt`. It enumerates, *tests* access, and hands the exploit
candidate down the chain:

```text
p0rtix      init / facts / recon / enum / test-access / offline-crack + the green->yellow->red noise floor  (you are here)
Metasploit  exploitation, sessions, privesc, post, pivoting   (via Metasploit MCP)
sliver-mcp  C2 — listeners, implant/beacon generation, sessions/beacons, execution
dagar-red   ATT&CK adversary-emulation skills — the judgment about which call to make next
```

`export_handoff` emits a structured inventory (hosts, domain, open ports, versioned services,
web tech, **exploit candidates** with CVE + msf module, valid/admin creds, hashes, relay
targets) that the exploitation/C2 agents ingest. See
[dagar-red](https://github.com/v0idravl/dagar-red) for the orchestration.

---

## 🛠 Install

- **Python 3.10+**, **root** (nmap SYN scans + `/etc/hosts` writes), Kali Linux recommended.

```bash
python3 -m venv venv
./venv/bin/pip install -e '.[mcp]'      # '.[mcp]' adds the MCP SDK; omit for CLI-only
```

Core tools (required; p0rtix prompts before installing): `nmap` · `curl` · `ffuf`.

Optional tools (used when present, skipped gracefully otherwise):

- **Web/general:** `whatweb` · `gospider` · `testssl.sh` · `wpscan` · `joomscan` · `droopescan` · `cewl` · `git-dumper` · `searchsploit` · `openssl`
- **SMB:** `nxc` · `smbclient` · `smbmap` · `enum4linux-ng`
- **AD / Kerberos:** `ldapsearch` · `ldapdomaindump` · `bloodhound-python` · `certipy-ad` · `kerbrute` · `impacket-GetNPUsers` · `impacket-GetUserSPNs` · `impacket-secretsdump` · `impacket-rpcdump` · `ntpdate`
- **Other services:** `onesixtyone` · `snmpwalk` · `snmp-check` · `dig` · `dnsrecon` · `mysql` · `psql` · `redis-cli` · `rsync` · `showmount` · `rpcinfo` · `smtp-user-enum` · `ipmitool`

---

## Usage

```bash
sudo python3 p0rtix.py <ip | --targets FILE> [OPTIONS]
```

### Examples

```bash
# Scan only — IP
sudo python3 p0rtix.py 10.10.11.34

# Scan only — IP + domain (enables AD enumeration and vhost busting)
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb

# Scan only — full options
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --name lame --workspace ~/htb --workers 8

# Multi-target — file with one entry per line: IP [domain [name]]
sudo python3 p0rtix.py --targets hosts.txt --workspace ~/htb

# Resume — continue a previous scan from where it left off
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --continue --workspace ~/htb

# Deep web scan — adds cewl wordlist, arjun param discovery, full API bust
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --deep --workspace ~/htb

# Creds mode — authenticated AD enumeration against a prior scan workspace
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --mode creds -u '<USERNAME>' -p '<PASSWORD>' --name assessment --workspace ~/engagements

# Combined — full scan then credentialed phase in one run (recommended)
sudo -E python3 p0rtix.py 10.10.11.34 --domain test.htb --mode scan,creds -u '<USERNAME>' -p '<PASSWORD>' --name assessment --workspace ~/engagements --analyze
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `ip` | — | Target IP address (mutually exclusive with `--targets`) |
| `--targets / -T` | — | File of targets, one per line: `IP [domain [name]]` |
| `--domain` | — | Primary domain (enables AD tools and vhost busting) |
| `--name` | domain or IP | Output directory name |
| `--workspace` | `.` | Root directory for all output |
| `--workers` | `6` | Parallel enumeration threads |
| `--mode` | `console` (or `scan,creds` with creds) | `scan` · `creds` · `scan,creds` · `console` · `mcp` |
| `-u / --username` | — | Username for creds mode |
| `-p / --password` | — | Password for creds mode |
| `--creds` | — | File of `user:pass` pairs for creds mode |
| `--analyze` | off | Send `findings.md` to Claude API for AI triage (requires `ANTHROPIC_API_KEY`; use `sudo -E`) |
| `--model` | `claude-sonnet-4-6` | Claude model for `--analyze` |
| `--verbose` | off | Include notes and searchsploit output in `findings.md` |
| `--deep` | off | Extended web scanning: cewl wordlist, arjun param discovery, full API bust (slower) |
| `--continue` | off | Resume a previous scan — skips completed phases |
| `--rescan` | off | Force fresh nmap scans even when prior scan data exists |
| `--no-install` | off | Never attempt dependency installation; fail if required tools are missing and skip optional tools |

---

## Creds Mode

`--mode creds` runs authenticated AD enumeration against an existing scan workspace.
`--mode scan,creds` does both in one invocation — preferred when you have credentials from the
start. Requires `-u/-p` (single credential) or `--creds <file>` (one `user:pass` per line);
`--domain` is strongly recommended.

### What it does

1. **SMB validation** — tests all credential pairs via nxc; identifies valid and admin accounts
2. **AD core enumeration** (requires `--domain`):
   - Clock sync to DC (`ntpdate`) — prevents Kerberos clock-skew failures
   - Full domain dump (`ldapdomaindump`) — sAMAccountNames extracted to `loot/users.txt`
   - Kerberoasting (`impacket-GetUserSPNs`) → `loot/kerberoast.hash`
   - AS-REP roasting (`impacket-GetNPUsers`) → `loot/asrep.hash`
   - BloodHound collection (`bloodhound-python`) → `loot/bloodhound/`
   - ADCS template enumeration and ESC1/ESC4 exploitation chain (see below)
   - Admin command execution and `secretsdump` if admin creds confirmed
3. **Per-service enumeration** — SMB share listing + spider, WinRM, SSH, FTP, MSSQL, RDP

### ADCS ESC chain

When `certipy-ad` finds a vulnerable certificate template, p0rtix automatically chains:

```
certipy-ad find -vulnerable   →   detect ESC1/ESC4
certipy-ad req                →   request cert as administrator@domain
certipy-ad auth               →   authenticate with PFX → NT hash
                              →   hash saved to loot/ntlm.hash + fed into cred-reuse
```

**ESC4** additionally patches the template first (`certipy-ad template -save-old`) and restores
it after. If `-vulnerable` returns nothing despite enabled templates existing, a fallback scan
runs with `-enabled` and saves the full JSON to `loot/certipy_full.json` for manual review.

---

## 🤖 MCP Mode (AI agent)

p0rtix can run as a [Model Context Protocol](https://modelcontextprotocol.io) server so an AI
agent (Claude) drives a complete, fact-driven recon process. The server registers **statically**
(no target at launch); the agent calls `open_target(ip)` to begin, so one registration serves
box after box.

```bash
pip install -e '.[mcp]'          # adds the `mcp` SDK
p0rtix-mcp --workspace ~/engagements
# or: python3 p0rtix.py --mode mcp --workspace ~/engagements
# (an optional trailing IP pre-opens one target: `p0rtix-mcp 10.10.11.34 --domain test.htb`)
```

It speaks stdio; point your agent's MCP client config at the `p0rtix-mcp` command. The agent's
first call is `open_target(ip, domain?)`.

**Doctrine — recon, not C2.** p0rtix owns reconnaissance and credentialed enumeration and stops
there: it tests access (`creds.test`) and runs a single command non-interactively (`access.exec`),
but never opens an interactive shell. Discovered facts leave via `export_handoff` for a separate
exploitation/C2 agent (Metasploit MCP / [sliver-mcp](https://github.com/v0idravl/sliver-mcp)).

**Tool surface (generic, mirrors the engine).** Every recon capability is an *action*; new
actions are callable with no new tool code:

| Tool | Purpose |
|------|---------|
| `open_target(ip, domain?, name?)` | start/resume a recon session — call first |
| `get_state` | discovered facts (ports, versioned services, **web tech**, **exploit candidates**, users, creds, hashes, signing) + progress + background-task state |
| `list_actions` | the catalogue with tier, group, footprint, and a `why` for planning |
| `run_action(name, port?, args?)` | run one action; returns `{summary, facts_delta, findings_md}` |
| `run_group(group)` / `run_all(noise?)` | run a branch / everything at/below the noise ceiling — aggregated across every sub-action |
| `start_full_scan` / `background_status` | kick a full TCP (`-p-`) sweep in the **background** while recon proceeds; poll for new ports |
| `set_noise(level)` | noise ceiling: `passive` → `green` → `yellow` → `red` (quiet by default) |
| `set_breadth(level)` | effort knob `concise` → `standard` → `broad` (wordlists/crack rules), orthogonal to noise |
| `arm_dangerous` | unlock RED-tier actions |
| `add_fact(kind, value)` · `reload` · `recheck` | seed/refresh facts |
| `export_handoff` | structured inventory (hosts, domain, open ports, versioned services, **web tech**, **exploit candidates** (CVE + msf module), valid/admin creds, hashes, relay target) |

The action catalogue spans discovery, **web** and **service** enumeration (databases, DNS, SNMP,
mail, RDP, …), **IKE/IPsec** (`ike.enum` — ISAKMP fingerprint + IKEv1 aggressive-mode probe that
leaks the responder's ID payload as a user/domain fact and a crackable PSK hash), anonymous
SMB/LDAP, Kerberos, offline cracking (hashcat for AS-REP/Kerberoast/NTLM, **psk-crack** for IKE
PSKs), credentialed AD (domaindump, Kerberoast, BloodHound, ADCS templates, writable objects),
SMB-signing/coercion **relay-target recon**, and non-interactive `access.exec`.

**Cross-protocol reuse** is built in: the moment a secret lands — a cracked hash, an IKE PSK, a
credential literal scraped from a downloadable artifact (`web.artifact_secrets` walks
`.jar/.zip/.war/.config/.sql`) — it re-arms `creds.spray`/`creds.test`, which fan it across
**every open auth surface** (SMB/WinRM/SSH/RDP/MSSQL), not just SMB. A `:80` redirect to a vhost
is promoted to a domain fact and followed with a transparent `Host:` header when it has no DNS
entry; linked JS endpoints (`fetch`/`$.get`/relative `.php`) are followed; WordPress authors
become user facts. This is what carries a box like Expressway end-to-end (IKE aggressive-mode →
PSK crack → SSH reuse) without operator hand-holding.

---

## Output Structure

```
<workspace>/<name>/
├── findings.md        ← primary read surface (live-updated during scan)
├── raw/               ← full tool output, each file headed by the exact command
│   ├── 01_full_tcp.{nmap,gnmap,xml}
│   ├── 02_udp_top100.{nmap,gnmap,xml}
│   ├── 04_tcp_services.{nmap,gnmap,xml}
│   └── ...
├── report/
│   └── report.md      ← writeup template (pre-populated)
├── loot/              ← credentials, hashes, interesting files
└── exploit/           ← payloads, custom exploits
```

### findings.md format

Each service gets its own section with the generating command noted above its output:

```markdown
### TCP 445 — SMB

#### SMB Enum
> `nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode -p 445 10.10.11.34`

- **MS17-010 (EternalBlue): VULNERABLE**
- Shares: IPC$ (READ), Data (READ), ADMIN$ (NO ACCESS)
```

---

## Scope Enforcement

p0rtix applies scope checks before crawler/follow-up enumeration and will not intentionally
launch follow-up tools against any host that is not:

- The target IP, **or**
- The explicitly provided domain / any subdomain of it (`*.domain`), **or**
- A hostname that resolves to the target IP

Crawled external URLs are surfaced in `findings.md` under *External Links* but are never touched
by any tool. Scope checks are a guardrail, not a replacement for an authorization letter or
rules of engagement.

---

## 🩹 Troubleshooting

| Symptom | Fix |
|---|---|
| `Operation not permitted` / no SYN results | Run with `sudo` — SYN scans and `/etc/hosts` writes need root. |
| `--analyze` does nothing / auth error | Export `ANTHROPIC_API_KEY` and run with `sudo -E` so the env survives the sudo boundary. |
| A tool is "missing" mid-scan | p0rtix prompts before installing; accept, or pre-install it. Use `--no-install` to skip optional tools entirely. |
| Kerberos `KRB_AP_ERR_SKEW` in creds mode | Clock skew vs the DC — p0rtix runs `ntpdate`, but ensure it is installed and reachable. |
| MCP server not found by the agent | Point the MCP client at the `p0rtix-mcp` entry point from `pip install -e '.[mcp]'`; it speaks stdio. |
| Re-running re-scans everything | Use `--continue` to skip completed phases; `--rescan` forces fresh nmap. |

See [`docs/sample-findings.md`](docs/sample-findings.md) for a sanitized example of the generated
`findings.md`, and [`docs/operator-console.md`](docs/operator-console.md) for the interactive
console.

---

## License

For **educational and authorized testing purposes only** — see [`LICENSE`](LICENSE). Use
responsibly, preserve evidence, and operate only within written scope.
