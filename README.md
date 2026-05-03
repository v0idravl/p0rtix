# p0rtix

A modular port scanning and enumeration toolkit for penetration testing and reconnaissance.

## Overview

p0rtix automates the process of discovering open ports, enumerating services, and identifying potential vulnerabilities on target systems. It follows a structured approach: discovery → web enumeration → service enumeration, with organized output directories.

## Features

- **Modular Design**: Separate scripts for orchestration, discovery, web, and service enumeration
- **Comprehensive Scanning**: TCP port discovery, UDP top ports, service versioning, and OS detection
- **Web Enumeration**: HTTP/HTTPS header collection, robots.txt, sitemap, whatweb, gobuster directory enumeration on standard and non-standard web ports
- **Service Enumeration**: Targeted checks for FTP, SSH, DNS, SMB, SNMP, RPC/NFS, WinRM, and more
- **Vulnerability Scanning**: Service-specific NSE vuln scripts (excluding DoS)
- **High-ROI NSE Defaults**: Uses a small curated NSE shortlist intended to add signal beyond `-sC` without producing a lot of duplicate noise
- **Organized Output**: Results saved under `<project-root>/<machine-name>/output/{scans,web,services}/`
- **Machine Workspace Bootstrap**: Creates per-machine `loot/`, `exploit/`, and report template files
- **Safe Execution**: All scripts use `set -euo pipefail` for robust error handling
- **Dependency Preflight**: Reports required and optional tooling before scans begin, with clear skip behavior for missing optional helpers

## Project Structure

```
p0rtix/
├── main.sh          # Orchestrator script - runs the full pipeline
├── ports.sh         # Discovery stage - finds open ports and runs version scans
├── web.sh           # Web enumeration - HTTP/HTTPS specific checks
├── services.sh      # Non-web service enumeration - targeted service checks
├── README.md        # This file
└── <machine-name>/
    ├── output/
    │   ├── scans/     # Port discovery and version scan results
    │   ├── web/       # Web enumeration outputs
    │   └── services/  # Non-web service outputs
    ├── loot/          # Loot gathered during enumeration/exploitation
    ├── exploit/       # Exploit helpers, notes, and payloads
    └── <machine-name>_report.md
```

## Dependencies

- **nmap**: Core scanning tool
- **gobuster**: Directory enumeration (optional, requires wordlist)
- **whatweb**: Web technology fingerprinting
- **snmpwalk**: SNMP enumeration
- **enum4linux-ng**: SMB enumeration
- **showmount**: NFS export enumeration
- **curl**: HTTP requests
- **xmllint**: XML formatting (optional)

Install on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install nmap gobuster whatweb snmp snmp-mibs-downloader enum4linux-ng nfs-common curl libxml2-utils
```

For gobuster wordlist:
```bash
sudo apt install seclists  # or download manually to /usr/share/seclists/
```

## Installation

1. Clone or download the scripts
2. Make them executable:
   ```bash
   chmod +x main.sh ports.sh web.sh services.sh
   ```
3. Run from the project directory

## Usage

### Full Pipeline (Recommended)
```bash
./main.sh <target-ip-or-hostname> [project-root-dir] [machine-nickname]
```

Example:
```bash
./main.sh 192.168.1.100 /home/user/Projects/htb lame
```

If you omit any argument, you'll be prompted for it. The project root defaults to the repository directory, and the machine nickname defaults to a sanitized version of the target.

### Individual Scripts

#### Port Discovery Only
```bash
./ports.sh <target> <output-base-dir>
```

#### Web Enumeration Only
```bash
./web.sh <target> <web-ports> <output-base-dir>
```

#### Service Enumeration Only
```bash
./services.sh <target> <service-ports> <output-base-dir>
```

## Output Structure

Results are organized under `<project-root>/<machine-name>/`:

- **output/scans/**: Raw nmap outputs (.gnmap, .nmap, .xml), parsed port lists
- **output/web/**: HTTP headers, robots.txt, sitemap, whatweb, gobuster results
- **output/services/**: Service-specific enumeration outputs (SSH keys, SMB info, etc.)
- **loot/**: Manual findings and captured artifacts
- **exploit/**: Exploit code, payloads, or attack notes
- **`<machine-name>_report.md`**: Writeup template downloaded from the shared template repo

## What Each Script Does

### main.sh (Orchestrator)
- Defines the target
- Creates machine workspace directories
- Runs a dependency preflight for required and optional tools
- Calls ports.sh for discovery
- Conditionally calls web.sh if ports are identified as HTTP/HTTPS services
- Conditionally calls services.sh if non-web ports are found
- Downloads a machine report template if one does not already exist

### ports.sh (Discovery)
- Runs full TCP scan (all ports)
- Runs UDP top 100 ports scan
- Runs a lightweight TCP service classification scan on open TCP ports
- Separates web ports from non-web ports based on detected service, not only port number
- Writes the port lists consumed by the web and service enumeration stages

### web.sh (Web Enumeration)
- Runs a per-port baseline `-sV -sC` scan for each web service
- Chooses `http://` vs `https://` for each port using detected service data, including common non-standard TLS ports
- Collects HTTP headers
- Fetches robots.txt, sitemap.xml, crossdomain.xml, etc.
- Runs whatweb for technology fingerprinting
- Runs gobuster directory enumeration (if wordlist available)
- Runs a fixed high-ROI NSE shortlist for that web port

### services.sh (Service Enumeration)
- Runs a per-port baseline `-sV -sC` scan for each non-web TCP service
- Records discovered UDP ports in a notes file and skips blanket UDP follow-up by default
- Runs targeted UDP follow-up only for a small high-value allowlist
- Runs a fixed high-ROI NSE shortlist for each service port that receives follow-up scanning
- Runs `enum4linux-ng -A` once when SMB is identified
- Runs `showmount -e` once when NFS is identified
- Performs an extra `snmpwalk -v2c -c public` check on UDP 161

## Examples

### Basic Scan
```bash
./main.sh example.com /home/user/Projects/labs example
```

Output:
```
/home/user/Projects/labs/example/
├── output/
│   ├── scans/
│   │   ├── full_tcp.gnmap
│   │   ├── open_tcp_ports.txt
│   │   └── top_100_udp.nmap
│   ├── web/
│   │   ├── example.com_80_baseline.txt
│   │   ├── example.com_80_headers.txt
│   │   ├── example.com_80_whatweb.txt
│   │   └── example.com_80_nse.txt
│   └── services/
│       ├── example.com_services_tcp_22_baseline.txt
│       └── example.com_services_tcp_22_nse.txt
├── loot/
├── exploit/
└── example_report.md
```

### Targeted Web Scan
```bash
./web.sh 10.0.0.1 80,443 output/10.0.0.1
```

## Notes

- All scans are designed to be non-intrusive and avoid DoS
- Vuln scripts are service-specific and exclude denial-of-service checks
- Scripts use `2>/dev/null || true` to continue on errors
- Output directories are created automatically
- For large scans, consider adjusting nmap timing options in the scripts

## License

This project is for educational and authorized testing purposes only. Use responsibly and in compliance with applicable laws.
