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
