# p0rtix

Stealthy, coverage-focused recon and enumeration. Finds everything available on a remote host while keeping as low a profile as possible.

Built around a personal methodology reference ([hakiki](https://github.com/v0idravl/hakiki)) — covers
port discovery, per-service enumeration, web directory/vhost busting, crawling, and SSL inspection.
Results are written to a single `findings.md` as the scan progresses, with all raw tool output
archived separately so nothing is lost.

---

## Features

- Full TCP SYN scan + top-100 UDP with automatic confirmation of open|filtered ports
- Service classification — routes web ports to web enumeration, everything else to per-service handlers
- **Web:** headers, WhatWeb fingerprint, redirect detection, SSL cert SAN extraction, directory bust, vhost bust, crawl (scope-filtered)
- **Services:** FTP, SSH, SMTP, DNS, RPC/NFS, MSRPC, SMB, SNMP, LDAP, Rsync, MSSQL, Oracle, MySQL, RDP, PostgreSQL, WinRM, Redis, MongoDB
- **Creds mode** (`--mode creds` or `--mode scan,creds`) — authenticated AD enumeration: SMB validation, ldapdomaindump, Kerberoasting, AS-REP roasting, BloodHound collection, ADCS ESC1/ESC4 chain, secretsdump
- Reactive follow-up — discovered vhosts and SSL SANs prompt for `/etc/hosts` addition, then get fully enumerated
- Scope enforcement — crawl and follow-up scans never touch out-of-scope hosts
- Single `findings.md` updated in real time (key findings only)
- `raw/` directory with every tool's full output, each file headed by the exact command
- Auto-installs missing tools via `apt`, `pip`, or `go install`

---

## Requirements

- **Python 3.10+**
- **Root** (required for nmap SYN scans and `/etc/hosts` writes)
- Kali Linux recommended — most tools already present

Core tools (required, installed automatically if missing):

| Tool | Purpose |
|------|---------|
| `nmap` | Port discovery and service scripts |
| `curl` | HTTP probing |
| `ffuf` | Directory and vhost busting |

Optional tools (used when present, skipped gracefully otherwise):

**Web/general:** `whatweb` · `gospider` · `testssl.sh` · `wpscan` · `joomscan` · `droopescan` · `cewl` · `git-dumper` · `searchsploit` · `openssl`

**SMB:** `nxc` · `smbclient` · `smbmap` · `enum4linux-ng`

**Active Directory / Kerberos:** `ldapsearch` · `ldapdomaindump` · `bloodhound-python` · `certipy-ad` · `kerbrute` · `impacket-GetNPUsers` · `impacket-GetUserSPNs` · `impacket-secretsdump` · `impacket-rpcdump` · `ntpdate`

**Other services:** `onesixtyone` · `snmpwalk` · `snmp-check` · `dig` · `dnsrecon` · `mysql` · `psql` · `redis-cli` · `rsync` · `showmount` · `rpcinfo` · `smtp-user-enum` · `ipmitool`

---

## Usage

```bash
sudo python3 p0rtix.py <ip> [OPTIONS]
```

### Examples

```bash
# Scan only — IP
sudo python3 p0rtix.py 10.10.11.34

# Scan only — IP + domain (enables AD enumeration and vhost busting)
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb

# Scan only — full options
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --name lame --workspace ~/htb --workers 8

# Creds mode — authenticated AD enumeration against a prior scan workspace
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --mode creds -u judith.mader -p judith09 --name certified --workspace ~/htb

# Combined — full scan then credentialed phase in one run (recommended)
sudo -E python3 p0rtix.py 10.10.11.34 --domain test.htb --mode scan,creds -u judith.mader -p judith09 --name certified --workspace ~/htb --analyze
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `ip` | — | Target IP address |
| `--domain` | — | Primary domain (enables AD tools and vhost busting) |
| `--name` | domain or IP | Output directory name |
| `--workspace` | `.` | Root directory for all output |
| `--workers` | `6` | Parallel enumeration threads |
| `--mode` | `scan` | `scan` · `creds` · `scan,creds` |
| `-u / --username` | — | Username for creds mode |
| `-p / --password` | — | Password for creds mode |
| `--creds` | — | File of `user:pass` pairs for creds mode |
| `--analyze` | off | Send `findings.md` to Claude API for AI triage (requires `ANTHROPIC_API_KEY`; use `sudo -E`) |
| `--verbose` | off | Include notes and searchsploit output in `findings.md` |

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

p0rtix will not scan any host that is not:
- The target IP, **or**
- The explicitly provided domain / any subdomain of it (`*.domain`), **or**
- A hostname that resolves to the target IP

Crawled external URLs are surfaced in `findings.md` under *External Links* but are never touched by any tool.

---

## License

For educational and authorized testing purposes only. Use responsibly and lawfully.
