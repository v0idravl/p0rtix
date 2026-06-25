# p0rtix

Scope-aware reconnaissance and enumeration for authorized security assessments. p0rtix is designed to help junior/internal pentesters collect repeatable evidence, keep raw output intact, and avoid follow-up activity outside the agreed target scope.

Built around a personal methodology reference ([hakiki](https://github.com/v0idravl/hakiki)) — covers
port discovery, per-service enumeration, web directory/vhost busting, crawling, and SSL inspection.
Results are written to a single `findings.md` as the scan progresses, with all raw tool output
archived separately so nothing is lost.

> **Authorized use only:** Run p0rtix only against systems where you have explicit permission and a documented scope. The tool preserves evidence and filters follow-up discovery, but the operator remains responsible for rate limits, rules of engagement, and legal authorization.

---

## Features

- Full TCP SYN scan + top-100 UDP with automatic confirmation of open|filtered ports
- Service classification — routes web ports to web enumeration, everything else to per-service handlers
- **Web:** headers, WhatWeb fingerprint, redirect detection, SSL cert SAN extraction, directory bust, vhost bust, crawl (scope-filtered)
- **Services:** FTP, SSH, SMTP, DNS, RPC/NFS, MSRPC, SMB, SNMP, LDAP, Rsync, MSSQL, Oracle, MySQL, RDP, PostgreSQL, WinRM, Redis, MongoDB
- **Creds mode** (`--mode creds` or `--mode scan,creds`) — authenticated AD enumeration in authorized environments: SMB validation, ldapdomaindump, Kerberoasting, AS-REP roasting, BloodHound collection, ADCS template review, and evidence capture
- **MCP server** (`--mode mcp` / `p0rtix-mcp`) — drives the recon engine from an AI agent (Claude) over the Model Context Protocol. A small generic tool surface (`list_actions`, `run_action`, `run_all`, `get_state`, `set_noise`, `set_breadth`, `export_handoff`) exposes the full fact-driven action catalogue; quiet/surgical by default via the noise ladder, with `export_handoff` emitting a structured inventory (creds, hosts, services, hashes, relay targets) for an exploitation agent (e.g. metasploitmcp). Recon only — it tests access and runs single commands non-interactively, never an interactive shell
- Reactive follow-up — discovered vhosts and SSL SANs prompt for `/etc/hosts` addition, then get fully enumerated
- Scope enforcement — crawl and follow-up scans never touch out-of-scope hosts
- Single `findings.md` updated in real time (key findings only)
- `raw/` directory with every tool's full output, each file headed by the exact command
- Prompts before installing missing tools via `apt`, `pip`/`pipx`, `go install`, or selected GitHub release downloads

---

## What this demonstrates

- Practical Python orchestration around common pentest tools without hiding raw evidence
- Scope-aware follow-up logic for crawled URLs, vhosts, SSL SANs, and resolved hostnames
- Incremental findings generation suitable for internal notes and handoff
- Resume/reuse of prior scan data to avoid unnecessary repeat network activity
- Credentialed AD workflow support for authorized environments, with loot separated from summary reporting

---

## Requirements

- **Python 3.10+**
- **Root** (required for nmap SYN scans and `/etc/hosts` writes)
- Kali Linux recommended — most tools already present

Core tools (required; if missing, p0rtix prompts before attempting installation):

| Tool | Purpose |
|------|---------|
| `nmap` | Port discovery and service scripts |
| `curl` | HTTP probing |
| `ffuf` | Directory and vhost busting |

Optional tools (used when present, skipped gracefully otherwise; p0rtix prompts before attempting installation):

**Web/general:** `whatweb` · `gospider` · `testssl.sh` · `wpscan` · `joomscan` · `droopescan` · `cewl` · `git-dumper` · `searchsploit` · `openssl`

**SMB:** `nxc` · `smbclient` · `smbmap` · `enum4linux-ng`

**Active Directory / Kerberos:** `ldapsearch` · `ldapdomaindump` · `bloodhound-python` · `certipy-ad` · `kerbrute` · `impacket-GetNPUsers` · `impacket-GetUserSPNs` · `impacket-secretsdump` · `impacket-rpcdump` · `ntpdate`

**Other services:** `onesixtyone` · `snmpwalk` · `snmp-check` · `dig` · `dnsrecon` · `mysql` · `psql` · `redis-cli` · `rsync` · `showmount` · `rpcinfo` · `smtp-user-enum` · `ipmitool`

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

`--mode creds` runs authenticated AD enumeration against an existing scan workspace. `--mode scan,creds` does both in one invocation — preferred when you have credentials from the start.

Requires `-u/-p` (single credential) or `--creds <file>` (one `user:pass` per line). `--domain` is strongly recommended.

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

**ESC4** additionally patches the template first (`certipy-ad template -save-old`) and restores it after.

If `-vulnerable` returns nothing despite enabled templates existing, a fallback scan runs with `-enabled` and saves the full JSON to `loot/certipy_full.json` for manual review.

---

## MCP Mode (AI agent)

p0rtix can run as a [Model Context Protocol](https://modelcontextprotocol.io) server so an AI agent (Claude) drives a complete, fact-driven recon process. Install the optional dependency and launch against a target:

```bash
pip install -e '.[mcp]'          # adds the `mcp` SDK
p0rtix-mcp 10.10.11.34 --domain test.htb --workspace ~/engagements
# or: python3 p0rtix.py 10.10.11.34 --domain test.htb --mode mcp
```

It speaks stdio; point your agent's MCP client config at the `p0rtix-mcp` command.

**Doctrine — recon, not C2.** p0rtix owns reconnaissance and credentialed enumeration and stops there: it tests access (`creds.test`) and runs a single command non-interactively (`access.exec`), but never opens an interactive shell. Discovered facts leave via `export_handoff` for a separate exploitation agent (e.g. metasploitmcp).

**Tool surface (generic, mirrors the engine).** Every recon capability is an *action*; new actions are callable with no new tool code:

| Tool | Purpose |
|------|---------|
| `get_state` | discovered facts (ports, users, creds, hashes, signing) + scheduler status |
| `list_actions` | the catalogue with tier, group, footprint, and a `why` for planning |
| `run_action(name, port?, args?)` | run one action; returns `{summary, facts_delta, findings_md}` |
| `run_group(group)` / `run_all(noise?)` | run a branch / everything at/below the noise ceiling |
| `set_noise(level)` | noise ceiling: `passive` → `green` → `yellow` → `red` (quiet by default) |
| `set_breadth(level)` | effort knob `concise` → `standard` → `broad` (wordlists/crack rules), orthogonal to noise |
| `arm_dangerous` | unlock RED-tier actions |
| `add_fact(kind, value)` · `reload` · `recheck` | seed/refresh facts |
| `export_handoff` | structured inventory (hosts, domain, open ports, valid/admin creds, hashes, relay target) |

The action catalogue spans discovery, **web** and **service** enumeration (databases, DNS, SNMP, mail, RDP, …), anonymous SMB/LDAP, Kerberos, offline cracking, credentialed AD (domaindump, Kerberoast, BloodHound, ADCS templates, writable objects), SMB-signing/coercion **relay-target recon**, and non-interactive `access.exec`.

---

## Output Structure

```
<workspace>/<name>/
├── findings.md        ← primary read surface (live-updated during scan)
├── raw/               ← full tool output, each file headed by the exact command
│   ├── 01_full_tcp.{nmap,gnmap,xml}
│   ├── 02_udp_top100.{nmap,gnmap,xml}
│   ├── 03_udp_confirmed.{nmap,gnmap,xml}
│   ├── 04_tcp_services.{nmap,gnmap,xml}
│   ├── 05_smb_445_nmap_enum.txt
│   ├── 06_web_http_10_10_11_34_headers.txt
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

#### Vhost Bust
> `ffuf -u http://10.10.11.34 -H "Host: FUZZ.test.htb" -w subdomains-top1million-5000.txt -fs 892`

- **admin.test.htb** — status 200, size 4823
```

---

## Scope Enforcement

p0rtix applies scope checks before crawler/follow-up enumeration and will not intentionally launch follow-up tools against any host that is not:
- The target IP, **or**
- The explicitly provided domain / any subdomain of it (`*.domain`), **or**
- A hostname that resolves to the target IP

Crawled external URLs are surfaced in `findings.md` under *External Links* but are never touched by any tool.

Scope checks are a guardrail, not a replacement for an authorization letter or rules of engagement. Confirm targets, domains, rate expectations, and credential-use permissions before running scans.

---

## Sample Output

See [`docs/sample-findings.md`](docs/sample-findings.md) for a small sanitized example of the generated `findings.md` format.

---

## License

For educational and authorized testing purposes only. Use responsibly, preserve evidence, and operate only within written scope.
