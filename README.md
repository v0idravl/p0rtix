# p0rtix

A small, opinionated first-pass recon toolkit for quickly identifying exposed services and obvious web surface area.

## Scope

`p0rtix` is intentionally capped at initial recon.

It does:
- Full TCP port discovery
- Top 100 UDP discovery
- Lightweight TCP service classification
- Basic non-web follow-up scans
- Basic web follow-up scans

It does not try to do:
- Workspace bootstrapping
- Report template downloads
- Deep service-specific helper automation
- Default NSE-heavy follow-up
- Directory brute forcing
- Full exploitation prep

## Project Structure

```text
p0rtix/
├── main.sh       # Orchestrates the first-pass recon workflow
├── ports.sh      # Discovery and web/non-web classification
├── services.sh   # Lightweight batch follow-up for non-web ports
├── web.sh        # Lightweight follow-up for web ports
├── log_utils.sh  # Shared logging helpers
└── README.md
```

## Dependencies

Required:
- `nmap`

Optional:
- `curl` for HTTP headers and `robots.txt`
- `whatweb` for web fingerprinting

Install on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install nmap curl whatweb
```

## Usage

Run the full workflow:

```bash
./main.sh <target-ip-or-hostname> [project-root-dir] [machine-nickname]
```

Examples:

```bash
./main.sh 10.10.11.34
./main.sh 10.10.11.34 /home/user/Projects/htb lame
```

You must provide the target explicitly. If `project-root-dir` is omitted, the repository directory is used. If `machine-nickname` is omitted, a sanitized form of the target is used.

## Output Structure

Results are written under:

```text
<project-root>/<machine-name>/output/
├── scans/
├── services/
└── web/
```

Typical outputs:

- `output/scans/full_tcp.*`
- `output/scans/top_100_udp.*`
- `output/scans/open_tcp_services.nmap`
- `output/scans/web_ports.txt`
- `output/scans/non_web_ports.txt`
- `output/scans/non_web_udp_ports.txt`
- `output/services/<target>_services_tcp_baseline.txt`
- `output/services/<target>_services_udp_baseline.txt`
- `output/web/<target>_<port>_baseline.txt`
- `output/web/<target>_<port>_headers.txt`
- `output/web/<target>_<port>_robots.txt`
- `output/web/<target>_<port>_whatweb.txt`

## What Each Script Does

### `main.sh`
- Validates arguments
- Creates the output directories
- Runs discovery
- Runs lightweight non-web follow-up if non-web ports are found
- Runs lightweight web follow-up if web ports are found

### `ports.sh`
- Runs a full TCP scan
- Runs a top 100 UDP scan
- Runs a lightweight TCP service classification scan
- Splits open TCP ports into web and non-web buckets

### `services.sh`
- Runs one batch TCP baseline follow-up scan for non-web TCP ports
- Runs one batch UDP version follow-up scan for discovered non-web UDP ports

### `web.sh`
- Runs a baseline `-sC -sV` scan for each detected web port
- Chooses `http` or `https` heuristically
- Captures HTTP headers when `curl` is available
- Fetches `robots.txt` when `curl` is available
- Runs `whatweb` when installed

## Notes

- The default workflow is meant to be fast and low-complexity.
- Deeper enumeration is expected to be manual or handled by separate tooling.
- Missing optional tools are reported and skipped cleanly.

## License

This project is for educational and authorized testing purposes only. Use responsibly and lawfully.
