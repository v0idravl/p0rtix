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
- Reactive follow-up — discovered vhosts and SSL SANs prompt for `/etc/hosts` addition, then get fully enumerated
- Scope enforcement — crawl and follow-up scans never touch out-of-scope hosts
- Single `findings.md` updated in real time (key findings only)
- `raw/` directory with every tool's full output, each file headed by the exact command
- Auto-installs missing tools via `apt` or `go install`

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

`whatweb` · `gospider` · `testssl.sh` · `nxc` · `smbclient` · `smbmap` · `onesixtyone` · `snmpwalk` · `ldapsearch` · `dig` · `dnsrecon` · `mysql` · `redis-cli` · `rsync` · `showmount` · `rpcinfo` · `impacket-rpcdump` · `smtp-user-enum` · `searchsploit` · `openssl`

---

## Usage

```bash
sudo python3 p0rtix.py <ip> [--domain DOMAIN] [--name NAME] [--workspace DIR] [--workers N]
```

### Examples

```bash
# IP only
sudo python3 p0rtix.py 10.10.11.34

# IP + domain (enables vhost busting)
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb

# Full options
sudo python3 p0rtix.py 10.10.11.34 --domain test.htb --name lame --workspace ~/Projects/htb --workers 8
```

### Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `ip` | — | Target IP address |
| `--domain` | — | Primary domain for vhost busting |
| `--name` | domain or IP | Output directory name |
| `--workspace` | `.` | Root directory for all output |
| `--workers` | `6` | Parallel enumeration threads |

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
