import xml.etree.ElementTree as ET
from pathlib import Path

from lib.findings import Findings
from lib.models import Service
from lib.runner import Runner
from lib.workspace import Workspace

# Ports that should be treated as web regardless of the service name nmap reports
_WEB_PORTS = {
    80, 81, 280, 443, 591, 3000, 4848, 5000,
    7001, 7443, 8000, 8008, 8080, 8081, 8082, 8088,
    8443, 8888, 9000, 9090, 9443,
}

# Service name substrings that indicate HTTP/HTTPS regardless of port
_WEB_NAMES = {"http", "https", "ssl/http", "http-alt", "http-proxy", "sun-answerbook"}

# Service names that look HTTP-ish but are actually RPC transports — not web targets
_RPC_HTTP_NAMES = {"ncacn_http", "http-rpc-epmap"}

# WinRM uses HTTP as transport but is not a browseable web service; has its own handler
_WINRM_PORTS = {5985, 5986}


def _is_web(port: int, service_name: str) -> bool:
    name = service_name.lower()
    if port in _WINRM_PORTS:
        return False
    if any(n == name for n in _RPC_HTTP_NAMES):
        return False
    if any(n in name for n in _WEB_NAMES):
        return True
    return port in _WEB_PORTS


def _scheme(port: int, service_name: str) -> str:
    name = service_name.lower()
    if "ssl" in name or "https" in name or port in (443, 8443, 9443, 7443):
        return "https"
    return "http"


# ── Discovery phase ───────────────────────────────────────────────────────────

def run_port_discovery(ip: str, runner: Runner, ws: Workspace, findings: Findings) -> dict:
    """
    Full TCP SYN scan + top-100 UDP scan.
    Returns {"tcp": [22, 80, ...], "udp": [161, ...]}.
    """
    findings.h2("Port Discovery")

    # Full TCP — using -oA so nmap creates .nmap / .gnmap / .xml itself
    tcp_prefix = str(ws.raw_dir / "01_full_tcp")
    print("[*] nmap — full TCP SYN scan (-p-), this may take a few minutes...")
    runner.run_live(
        [
            "nmap", "-n", "--reason", "-sS", "-Pn", "-p-", "--open",
            "--min-rate", "2000", "--max-retries", "2", "--stats-every", "60s",
            "-oA", tcp_prefix, ip,
        ],
        label="01_full_tcp",
    )

    tcp_ports = _parse_xml_ports(Path(tcp_prefix + ".xml"), "tcp", include_filtered=False)
    print(f"[+] TCP open: {_fmt_ports(tcp_ports)}")

    # Top-100 UDP
    udp_prefix = str(ws.raw_dir / "02_udp_top100")
    print("[*] nmap — top-100 UDP scan...")
    runner.run_live(
        [
            "nmap", "-n", "-sU", "-T3", "-Pn", "--top-ports", "100",
            "--stats-every", "60s", "-oA", udp_prefix, ip,
        ],
        label="02_udp_top100",
    )

    udp_candidates = _parse_xml_ports(Path(udp_prefix + ".xml"), "udp", include_filtered=True)

    # A second pass confirms open|filtered UDP candidates via a lightweight version probe
    udp_ports: list[int] = []
    if udp_candidates:
        print(f"[*] nmap — confirming {len(udp_candidates)} UDP candidate(s)...")
        udp_confirm_prefix = str(ws.raw_dir / "03_udp_confirmed")
        runner.run_live(
            [
                "nmap", "-n", "-sU", "-sV", "--version-intensity", "0", "-Pn",
                "-p", ",".join(str(p) for p in sorted(udp_candidates)),
                "--stats-every", "60s", "-oA", udp_confirm_prefix, ip,
            ],
            label="03_udp_confirmed",
        )
        udp_ports = _parse_xml_ports(
            Path(udp_confirm_prefix + ".xml"), "udp", include_filtered=False
        )

    print(f"[+] UDP open: {_fmt_ports(udp_ports)}")
    return {"tcp": sorted(tcp_ports), "udp": sorted(udp_ports)}


# ── Engine: on-demand carve-outs ──────────────────────────────────────────────
# The engine drives discovery a step at a time: a quiet open-only sweep first
# (green), then version detection only when the operator asks for it (per port).
# These reuse the same nmap invocations / parsers as the legacy phase functions
# above, just split so version detection is no longer automatic.

# Curated quiet sweep: the ports an internal-AD foothold actually cares about
# (DCs, SMB/LDAP/Kerberos/ADCS/WinRM, common services). ~60 ports → fast & low
# noise, run before committing to a full -p- sweep.
QUICK_TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 161, 389, 443, 445,
    464, 465, 587, 593, 636, 873, 993, 995, 1433, 2049, 2375, 3128, 3268, 3269,
    3306, 3389, 5432, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9389, 11211,
    47001, 49152, 49664, 49665, 49666, 49667, 49668,
]


# General internal-pentest sweep: not AD-specific — Linux/Unix services, web,
# databases, remote access, mail, etc. The companion to QUICK_TCP_PORTS for the
# mixed hosts a typical engagement turns up (the same access principles apply,
# e.g. an SSH cred → shell, a DB cred → access).
COMMON_TCP_PORTS = [
    21, 22, 23, 25, 53, 79, 80, 110, 111, 113, 119, 135, 139, 143, 161, 179,
    264, 389, 443, 445, 465, 500, 512, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 636, 873, 990, 993, 995, 1080, 1099, 1433, 1521, 1723, 2049, 2082,
    2083, 2375, 2376, 3000, 3128, 3306, 3389, 4444, 5000, 5432, 5601, 5900,
    5985, 5986, 6000, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8443, 8888,
    9000, 9090, 9200, 9389, 10000, 11211, 27017,
]


def _quick_sweep(ip, runner, ws, ports, prefix, label) -> list[int]:
    spec = ",".join(str(p) for p in ports)
    runner.run_live(
        [
            "nmap", "-n", "--reason", "-sS", "-Pn", "-p", spec, "--open",
            "--min-rate", "1500", "--max-retries", "2", "-oA", prefix, ip,
        ],
        label=label,
    )
    return _parse_xml_ports(Path(prefix + ".xml"), "tcp", include_filtered=False)


def discover_tcp_quick(ip: str, runner: Runner, ws: Workspace) -> list[int]:
    """Quiet curated-port SYN sweep (~60 AD-relevant ports). Returns open ports;
    coverage is recorded by the caller so a later full sweep skips them."""
    return _quick_sweep(ip, runner, ws, QUICK_TCP_PORTS,
                        str(ws.raw_dir / "00_quick_tcp"), "00_quick_tcp")


def discover_tcp_common(ip: str, runner: Runner, ws: Workspace) -> list[int]:
    """Quiet curated sweep of common internal services (Linux/web/db/remote) —
    the non-AD companion profile."""
    return _quick_sweep(ip, runner, ws, COMMON_TCP_PORTS,
                        str(ws.raw_dir / "00_common_tcp"), "00_common_tcp")


def discover_tcp_open(ip: str, runner: Runner, ws: Workspace,
                      exclude: set[int] | None = None, *, live: bool = True) -> list[int]:
    """Open-only full TCP SYN sweep — NO version detection. Returns open ports.

    The quiet green discovery floor: what is listening, nothing more. `exclude`
    ports (already swept by an earlier tier) are skipped via --exclude-ports so a
    follow-up full sweep doesn't redo coverage.

    `live=True` streams progress to the terminal (console use). `live=False`
    captures silently — required when run from a background thread or under the
    MCP stdio server, where printing would corrupt the JSON-RPC stream."""
    tcp_prefix = str(ws.raw_dir / "01_full_tcp")
    cmd = [
        "nmap", "-n", "--reason", "-sS", "-Pn", "-p-", "--open",
        "--min-rate", "2000", "--max-retries", "2", "--stats-every", "60s",
    ]
    if exclude:
        cmd += ["--exclude-ports", ",".join(str(p) for p in sorted(exclude))]
    cmd += ["-oA", tcp_prefix, ip]
    if live:
        runner.run_live(cmd, label="01_full_tcp")
    else:
        # generous ceiling for a -p- sweep on a slow lab network; nmap writes the
        # XML via -oA regardless, so partial-on-timeout still yields what finished.
        runner.run(cmd, "01_full_tcp", timeout=1800)
    return _parse_xml_ports(Path(tcp_prefix + ".xml"), "tcp", include_filtered=False)


def discover_udp(ip: str, runner: Runner, ws: Workspace) -> list[int]:
    """Top-100 UDP sweep with a confirmation pass. Returns confirmed-open ports."""
    udp_prefix = str(ws.raw_dir / "02_udp_top100")
    runner.run_live(
        [
            "nmap", "-n", "-sU", "-T3", "-Pn", "--top-ports", "100",
            "--stats-every", "60s", "-oA", udp_prefix, ip,
        ],
        label="02_udp_top100",
    )
    candidates = _parse_xml_ports(Path(udp_prefix + ".xml"), "udp", include_filtered=True)
    if not candidates:
        return []
    confirm_prefix = str(ws.raw_dir / "03_udp_confirmed")
    runner.run_live(
        [
            "nmap", "-n", "-sU", "-sV", "--version-intensity", "0", "-Pn",
            "-p", ",".join(str(p) for p in sorted(candidates)),
            "--stats-every", "60s", "-oA", confirm_prefix, ip,
        ],
        label="03_udp_confirmed",
    )
    return _parse_xml_ports(Path(confirm_prefix + ".xml"), "udp", include_filtered=False)


def version_detect(ip: str, ports: list[int], runner: Runner, ws: Workspace) -> list[Service]:
    """On-demand `-sV` version detection on the given TCP ports. Returns Service
    objects. Carved out of the legacy service-scan phase so the engine can run it
    per port only when the operator wants it, instead of automatically."""
    if not ports:
        return []
    svc_prefix = str(ws.raw_dir / "04_tcp_services")
    runner.run_live(
        [
            "nmap", "-n", "-sS", "-sV", "--version-light", "-Pn",
            "-p", ",".join(str(p) for p in sorted(ports)),
            "--stats-every", "60s", "-oA", svc_prefix, ip,
        ],
        label="04_tcp_services",
    )
    return _parse_xml_services(Path(svc_prefix + ".xml"), "tcp")


# ── Service scan phase ────────────────────────────────────────────────────────

def run_service_scan(
    ip: str, ports: dict, runner: Runner, ws: Workspace, findings: Findings
) -> list[Service]:
    """
    Version detection on open TCP ports to classify web vs non-web services.
    UDP services are carried forward from discovery without re-scanning.
    """
    tcp_ports = ports.get("tcp", [])
    udp_ports = ports.get("udp", [])
    services: list[Service] = []

    if tcp_ports:
        print(f"[*] nmap — TCP service scan on {len(tcp_ports)} port(s)...")
        svc_prefix = str(ws.raw_dir / "04_tcp_services")
        runner.run_live(
            [
                "nmap", "-n", "-sS", "-sV", "--version-light", "-Pn",
                "-p", ",".join(str(p) for p in sorted(tcp_ports)),
                "--stats-every", "60s", "-oA", svc_prefix, ip,
            ],
            label="04_tcp_services",
        )
        services.extend(_parse_xml_services(Path(svc_prefix + ".xml"), "tcp"))

    # UDP confirmed ports come from the confirmation scan XML (03_udp_confirmed)
    # Reparse rather than run a new scan to avoid duplicate work
    udp_xml = ws.raw_dir / "03_udp_confirmed.xml"
    if udp_ports and udp_xml.exists():
        services.extend(_parse_xml_services(udp_xml, "udp"))
    elif udp_ports:
        # Fallback: build minimal Service objects if the XML is missing
        for p in udp_ports:
            services.append(Service(port=p, proto="udp", name="unknown", version="", is_web=False, scheme=""))

    write_port_table(services, findings)
    return services


# ── XML parsing ───────────────────────────────────────────────────────────────

def _parse_xml_ports(xml: Path, proto: str, include_filtered: bool) -> list[int]:
    if not xml.exists():
        return []
    try:
        tree = ET.parse(xml)
    except ET.ParseError:
        return []

    ports = []
    for el in tree.findall(f".//port[@protocol='{proto}']"):
        state_el = el.find("state")
        if state_el is None:
            continue
        state = state_el.get("state", "")
        if state == "open" or (include_filtered and state == "open|filtered"):
            ports.append(int(el.get("portid", 0)))
    return sorted(ports)


def _parse_xml_services(xml: Path, proto: str) -> list[Service]:
    if not xml.exists():
        return []
    try:
        tree = ET.parse(xml)
    except ET.ParseError:
        return []

    services = []
    for el in tree.findall(f".//port[@protocol='{proto}']"):
        state_el = el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        port = int(el.get("portid", 0))
        svc_el = el.find("service")
        name = svc_el.get("name", "unknown") if svc_el is not None else "unknown"
        product = (svc_el.get("product", "") if svc_el is not None else "").strip()
        ver = (svc_el.get("version", "") if svc_el is not None else "").strip()
        version_str = " ".join(filter(None, [product, ver]))

        web = _is_web(port, name)
        services.append(Service(
            port=port, proto=proto, name=name, version=version_str,
            is_web=web, scheme=_scheme(port, name) if web else "",
        ))

    return sorted(services, key=lambda s: s.port)


# ── Helpers ───────────────────────────────────────────────────────────────────

def write_port_table(services: list[Service], findings: Findings):
    findings.h2("Port Summary")
    rows = [
        [
            str(s.port),
            s.proto.upper(),
            s.name,
            s.version or "—",
            "web" if s.is_web else "service",
        ]
        for s in sorted(services, key=lambda s: s.port)
    ]
    findings.table(["Port", "Proto", "Service", "Version", "Type"], rows)


def _fmt_ports(ports: list[int]) -> str:
    return ", ".join(str(p) for p in sorted(ports)) if ports else "none"


def parse_service_xml(xml_path: Path, proto: str = "tcp") -> list[Service]:
    """Load Service objects from a saved nmap XML file (e.g. for --mode creds)."""
    return _parse_xml_services(xml_path, proto)
