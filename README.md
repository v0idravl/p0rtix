# p0rtix

A modular port scanning and enumeration toolkit for penetration testing and reconnaissance.

## Overview

p0rtix automates the process of discovering open ports, enumerating services, and identifying potential vulnerabilities on target systems. It follows a structured approach: discovery → web enumeration → service enumeration, with organized output directories.

## Features

- **Modular Design**: Separate scripts for orchestration, discovery, web, and service enumeration
- **Comprehensive Scanning**: TCP port discovery, UDP top ports, service versioning, and OS detection
- **Web Enumeration**: HTTP/HTTPS header collection, robots.txt, sitemap, whatweb, gobuster directory enumeration
- **Service Enumeration**: Targeted checks for FTP, SSH, DNS, SMB, SNMP, RPC/NFS, WinRM, and more
- **Vulnerability Scanning**: Service-specific NSE vuln scripts (excluding DoS)
- **Organized Output**: Results saved under `output/<target>/{scans,web,services}/`
- **Safe Execution**: All scripts use `set -euo pipefail` for robust error handling

## Project Structure

```
p0rtix/
├── main.sh          # Orchestrator script - runs the full pipeline
├── ports.sh         # Discovery stage - finds open ports and runs version scans
├── web.sh           # Web enumeration - HTTP/HTTPS specific checks
├── services.sh      # Non-web service enumeration - targeted service checks
├── README.md        # This file
└── output/          # Generated output directory (created on first run)
    └── <target>/
        ├── scans/   # Port discovery and version scan results
        ├── web/     # Web enumeration outputs
        ├── services/# Non-web service outputs
        └── summary.txt  # High-level summary
```

## Dependencies

- **nmap**: Core scanning tool
- **gobuster**: Directory enumeration (optional, requires wordlist)
- **whatweb**: Web technology fingerprinting
- **snmpwalk**: SNMP enumeration
- **curl**: HTTP requests
- **xmllint**: XML formatting (optional)

Install on Debian/Ubuntu:
```bash
sudo apt update
sudo apt install nmap gobuster whatweb snmp snmp-mibs-downloader curl libxml2-utils
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
./main.sh <target-ip-or-hostname>
```

Example:
```bash
./main.sh 192.168.1.100
```

If no target is provided, you'll be prompted to enter one.

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

Results are organized under `output/<target>/`:

- **scans/**: Raw nmap outputs (.gnmap, .nmap, .xml), parsed port lists
- **web/**: HTTP headers, robots.txt, sitemap, whatweb, gobuster results
- **services/**: Service-specific enumeration outputs (SSH keys, SMB info, etc.)
- **summary.txt**: Overview of discovered ports and scan results

## What Each Script Does

### main.sh (Orchestrator)
- Defines the target
- Creates output directories
- Calls ports.sh for discovery
- Conditionally calls web.sh if web ports (80/443) are found
- Conditionally calls services.sh if non-web ports are found
- Generates a summary

### ports.sh (Discovery)
- Runs fast TCP scan (top 1000 ports)
- Runs full TCP scan (all ports)
- Runs UDP top 100 ports scan
- Parses open TCP ports
- Separates web ports from non-web ports
- Runs service version scan on open ports

### web.sh (Web Enumeration)
- Collects HTTP headers
- Fetches robots.txt, sitemap.xml, crossdomain.xml, etc.
- Runs whatweb for technology fingerprinting
- Runs gobuster directory enumeration (if wordlist available)
- Runs HTTP vuln NSE scripts

### services.sh (Service Enumeration)
- Checks for specific services on discovered ports:
  - FTP (21): ftp NSE scripts + vuln
  - SSH (22): algorithm enum, hostkey, auth methods + vuln
  - DNS (53): DNS NSE scripts + vuln
  - RPC/NFS (111/2049): rpcinfo
  - SMB (139/445): OS discovery, enum, vuln scans
  - SNMP (161): snmpwalk + NSE scripts + vuln
  - WinRM (5985/5986): Windows HTTP scripts + vuln
- Skips web ports (handled by web.sh)

## Examples

### Basic Scan
```bash
./main.sh example.com
```

Output:
```
output/example.com/
├── scans/
│   ├── fast_tcp.gnmap
│   ├── full_tcp.gnmap
│   ├── open_tcp_ports.txt
│   └── service_version.nmap
├── web/
│   ├── example.com_80_headers.txt
│   ├── example.com_80_whatweb.txt
│   └── example.com_80_gobuster_dir.txt
├── services/
│   ├── example.com_services_ssh_algos.txt
│   └── example.com_services_smb_enum.txt
└── summary.txt
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
