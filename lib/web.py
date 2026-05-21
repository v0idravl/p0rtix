import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from lib.findings import FindingsSink as Findings
from lib.hosts import HostsManager
from lib.models import Discovery, Service
from lib.runner import Runner
from lib.scope import Scope

# SecLists paths
_WORDLIST_DIRS  = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
_WORDLIST_VHOST = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
_WORDLIST_API   = "/usr/share/seclists/Discovery/Web-Content/api/objects.txt"
_WEB_EXTENSIONS = ".php,.txt,.html,.bak,.zip,.old,.xml,.json,.config,.asp,.aspx,.jsp"

# ffuf result line: "path    [Status: 200, Size: 1234, ...]"
_FFUF_RE = re.compile(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+).*?\]", re.MULTILINE)

# Paths that indicate sensitive content if they return 200
_SENSITIVE_PATHS = [
    ("/.git/HEAD",             ".git exposed (use git-dumper)"),
    ("/.git/config",           ".git/config exposed"),
    ("/.env",                  ".env file exposed"),
    ("/.htpasswd",             ".htpasswd exposed"),
    ("/web.config",            "web.config exposed"),
    ("/phpinfo.php",           "phpinfo.php exposed"),
    ("/server-status",         "Apache server-status enabled"),
    ("/.svn/entries",          "SVN repository exposed"),
    ("/WEB-INF/web.xml",       "WEB-INF/web.xml exposed"),
    ("/.DS_Store",             ".DS_Store exposed"),
    ("/crossdomain.xml",       "crossdomain.xml (Flash policy)"),
    ("/clientaccesspolicy.xml","clientaccesspolicy.xml (Silverlight policy)"),
]

# ADCS web enrollment endpoints
_ADCS_PATHS = [
    "/certsrv",
    "/certsrv/certnew.asp",
    "/certenroll",
    "/certsrv/mscep/mscep.dll",
    "/ADPolicyProvider_CEP_UsernamePassword/service.svc",
]

# Jenkins paths — 200/403 means Jenkins is running
_JENKINS_PATHS = [
    ("/manage",         "Management interface"),
    ("/script",         "Script console (RCE if 200)"),
    ("/asynchPeople/",  "User list"),
    ("/systemInfo",     "System info"),
    ("/api/json",       "REST API"),
]


def enumerate_web(
    ip: str,
    service: Service,
    domain: str | None,
    runner: Runner,
    findings: Findings,
    scope: Scope,
    hosts: HostsManager,
    available: set[str],
    is_followup: bool = False,
) -> list[Discovery]:
    """
    Full web enumeration for one port/hostname.
    Returns Discovery objects (vhosts, SSL SANs, redirects) for follow-up.
    """
    port = service.port
    scheme = service.scheme
    hostname = service.hostname or (domain if domain and not is_followup else ip)
    base_url = _build_url(scheme, hostname, port)

    tag = f"TCP {port} — {scheme.upper()}"
    if hostname != ip:
        tag += f" ({hostname})"
    findings.h3(tag)
    print(f"[*] Web — {base_url}")

    discoveries: list[Discovery] = []

    # ── 1. Headers + tech fingerprint ─────────────────────────────────────────
    fp = _fingerprint(base_url, runner, findings, available)

    # ── 2. NTLM info disclosure (Windows/IIS auth header leaks hostname/domain) ─
    _check_ntlm_info(ip, port, runner, findings)

    # Microsoft-HTTPAPI endpoints (WinRM, RPC-over-HTTP) never have web content.
    # The fingerprint and NTLM check above are all that's useful; bail here.
    if "microsoft-httpapi" in fp["server"].lower():
        findings.note(
            f"Microsoft-HTTPAPI endpoint — no web content to enumerate. "
            f"WinRM: `evil-winrm -i {ip} -u USER -p PASS`"
        )
        return discoveries

    # ── 3. HTTP method probe ───────────────────────────────────────────────────
    _check_http_methods(base_url, runner, findings)

    # ── 4. Redirect detection (IP → domain) ───────────────────────────────────
    if not is_followup:
        redirect_host = _detect_redirect(ip, port, scheme)
        if redirect_host and redirect_host != ip and scope.check(redirect_host):
            findings.bullet(f"**Redirect:** `{_build_url(scheme, ip, port)}` → `{redirect_host}`")
            discoveries.append(Discovery(
                type="redirect", hostname=redirect_host,
                port=port, scheme=scheme, source=f"HTTP redirect on port {port}",
            ))

    # ── 5. robots.txt ─────────────────────────────────────────────────────────
    _fetch_robots(base_url, runner, findings)

    # ── 6. Sensitive file probes (.git, .env, phpinfo, etc.) ──────────────────
    _check_sensitive_files(base_url, runner, findings, available)

    # ── 7. SSL cert — extract CN / SANs ───────────────────────────────────────
    if scheme == "https":
        ssl_names = _extract_ssl_names(ip, port, runner, findings)
        for name in ssl_names:
            if name != hostname and scope.check(name):
                discoveries.append(Discovery(
                    type="ssl_san", hostname=name,
                    port=port, scheme="https", source=f"SSL certificate on port {port}",
                ))

    # ── 8. testssl.sh — SSL/TLS vulnerability scan ────────────────────────────
    if scheme == "https" and "testssl.sh" in available:
        _run_testssl(ip, port, runner, findings)

    # ── 9. ADCS probe (relevant on any web port on a DC) ──────────────────────
    _check_adcs(base_url, ip, runner, findings)

    # ── 10. WordPress detection + wpscan ──────────────────────────────────────
    if "wpscan" in available:
        _wpscan(base_url, runner, findings)

    # ── 11. CMS detection — Joomla + Drupal ───────────────────────────────────
    _check_cms(base_url, runner, findings, available)

    # ── 12. Jenkins probe ─────────────────────────────────────────────────────
    _check_jenkins(base_url, runner, findings)

    # ── 13. Directory + file bust ──────────────────────────────────────────────
    if "ffuf" in available:
        _dir_bust(base_url, runner, findings)

    # ── 14. API endpoint discovery ────────────────────────────────────────────
    if "ffuf" in available:
        _api_bust(base_url, runner, findings)

    # ── 15. cewl custom wordlist + targeted dir bust ──────────────────────────
    if "cewl" in available and "ffuf" in available:
        cewl_wl = _run_cewl(base_url, runner, findings)
        if cewl_wl:
            _dir_bust_cewl(base_url, cewl_wl, runner, findings)

    # ── 16. Vhost bust ────────────────────────────────────────────────────────
    if not is_followup and domain and "ffuf" in available:
        vhosts = _vhost_bust(ip, port, scheme, domain, runner, findings)
        for vh in vhosts:
            if scope.check(vh):
                discoveries.append(Discovery(
                    type="vhost", hostname=vh,
                    port=port, scheme=scheme, source=f"ffuf vhost bust port {port}",
                ))

    # ── 17. Crawl ─────────────────────────────────────────────────────────────
    if "gospider" in available:
        _crawl(base_url, scope, runner, findings)

    return discoveries


# ── Fingerprint ───────────────────────────────────────────────────────────────

def _fingerprint(url: str, runner: Runner, findings: Findings, available: set[str]) -> dict:
    findings.h4("Fingerprint")

    cmd = ["curl", "-sS", "-k", "-I", "-L", "--max-time", "15", url]
    out = runner.run(cmd, f"web_{_label(url)}_headers")
    findings.cmd(" ".join(cmd))
    _parse_interesting_headers(out, findings)

    meta = _parse_headers_meta(out)

    # Skip whatweb on HTTPAPI — it always times out on WinRM/RPC endpoints
    if "whatweb" in available and "microsoft-httpapi" not in meta["server"].lower():
        cmd2 = ["whatweb", "--no-errors", "-a", "3", url]
        out2 = runner.run(cmd2, f"web_{_label(url)}_whatweb", timeout=60)
        findings.cmd(" ".join(cmd2))
        if out2.strip():
            findings.code_block(out2.strip())

    return meta


def _parse_headers_meta(raw: str) -> dict:
    meta = {"status": "", "server": ""}
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2:
                meta["status"] = parts[1]
        elif ":" in line:
            key, _, val = line.partition(":")
            if key.strip().lower() == "server":
                meta["server"] = val.strip()
    return meta


def _parse_interesting_headers(raw: str, findings: Findings):
    interesting = {
        "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "location", "set-cookie", "www-authenticate", "content-security-policy",
        "x-frame-options", "access-control-allow-origin",
    }
    for line in raw.splitlines():
        if ":" in line:
            key = line.split(":", 1)[0].strip().lower()
            if key in interesting:
                findings.bullet(f"`{line.strip()}`")


# ── NTLM info disclosure ──────────────────────────────────────────────────────

def _check_ntlm_info(ip: str, port: int, runner: Runner, findings: Findings):
    """
    nmap http-ntlm-info script — Windows/IIS leaks NetBIOS computer name, DNS domain,
    and product version in the NTLM authentication challenge even without valid creds.
    """
    cmd = ["nmap", "--script", "http-ntlm-info", "-p", str(port), ip]
    out = runner.run(cmd, f"web_{ip}_{port}_ntlm_info", timeout=30)
    ntlm_fields = ("NetBIOS_Computer_Name", "NetBIOS_Domain_Name",
                   "DNS_Computer_Name", "DNS_Domain_Name", "Product_Version")
    hits = [l.strip() for l in out.splitlines()
            if any(f in l for f in ntlm_fields)]
    if hits:
        findings.h4("NTLM Info Disclosure")
        findings.cmd(" ".join(cmd))
        for line in hits:
            findings.bullet(f"`{line}`")


# ── HTTP method probe ─────────────────────────────────────────────────────────

def _check_http_methods(url: str, runner: Runner, findings: Findings):
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "-X", "OPTIONS", "-I", url],
        capture_output=True, text=True,
    )
    for line in result.stdout.splitlines():
        key = line.split(":", 1)[0].strip().lower()
        if key in ("allow", "access-control-allow-methods", "public"):
            methods = line.split(":", 1)[1].strip()
            dangerous = [m for m in ("PUT", "DELETE", "TRACE", "PATCH", "CONNECT")
                         if m in methods.upper()]
            if dangerous:
                findings.bullet(f"**Dangerous HTTP methods allowed:** `{', '.join(dangerous)}` (from `{methods}`)")
            else:
                findings.bullet(f"HTTP methods: `{methods}`")
            return


# ── Redirect detection ────────────────────────────────────────────────────────

def _detect_redirect(ip: str, port: int, scheme: str) -> str | None:
    url = _build_url(scheme, ip, port)
    result = subprocess.run(
        ["curl", "-sS", "-k", "-L", "--max-time", "15",
         "-o", "/dev/null", "-w", "%{url_effective}", url],
        capture_output=True, text=True,
    )
    effective = result.stdout.strip()
    if not effective:
        return None
    host = urlparse(effective).hostname or ""
    return host if host != ip else None


# ── robots.txt ────────────────────────────────────────────────────────────────

def _fetch_robots(base_url: str, runner: Runner, findings: Findings):
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "-o", "/dev/null",
         "-w", "%{http_code}", f"{base_url}/robots.txt"],
        capture_output=True, text=True,
    )
    if result.stdout.strip() not in ("200", "301", "302"):
        return

    cmd = ["curl", "-sS", "-k", "--max-time", "10", f"{base_url}/robots.txt"]
    out = runner.run(cmd, f"web_{_label(base_url)}_robots")
    if out.strip():
        findings.h4("robots.txt")
        findings.cmd(" ".join(cmd))
        findings.code_block(out.strip())


# ── Sensitive file probes ─────────────────────────────────────────────────────

def _check_sensitive_files(base_url: str, runner: Runner, findings: Findings,
                           available: set[str]):
    found: list[tuple[str, str]] = []
    for path, label in _SENSITIVE_PATHS:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        if result.stdout.strip() == "200":
            found.append((path, label))

    if found:
        findings.h4("Sensitive Files")
        for path, label in found:
            findings.bullet(f"**{label}**: `{base_url}{path}`")
            if ".git/HEAD" in path and "git-dumper" in available:
                git_out_dir = str(runner.ws.loot_dir / f"git_dump_{_label(base_url)}")
                cmd = ["git-dumper", f"{base_url}/.git/", git_out_dir]
                findings.cmd(" ".join(cmd))
                runner.run(cmd, f"web_{_label(base_url)}_git_dumper", timeout=300)
                findings.bullet(f"  git-dumper output: `{git_out_dir}`")


# ── SSL certificate ───────────────────────────────────────────────────────────

def _extract_ssl_names(ip: str, port: int, runner: Runner, findings: Findings) -> list[str]:
    cmd = ["openssl", "s_client", "-connect", f"{ip}:{port}",
           "-servername", ip, "-showcerts"]
    out = runner.run(cmd, f"web_{ip}_{port}_ssl_cert", timeout=15)

    cert_pem = _extract_pem(out)
    if not cert_pem:
        return []

    result = subprocess.run(
        ["openssl", "x509", "-noout", "-text"],
        input=cert_pem, capture_output=True, text=True,
    )
    cert_text = result.stdout

    names: list[str] = []
    cn = re.search(r"Subject:.*?CN\s*=\s*([^\s,/]+)", cert_text)
    if cn:
        names.append(cn.group(1).lstrip("*."))
    for m in re.finditer(r"DNS:([^\s,]+)", cert_text):
        names.append(m.group(1).lstrip("*."))

    unique = list(dict.fromkeys(n for n in names if n))
    if unique:
        findings.h4("SSL Certificate")
        for n in unique:
            findings.bullet(f"CN/SAN: `{n}`")

    return unique


def _extract_pem(openssl_out: str) -> str:
    start = openssl_out.find("-----BEGIN CERTIFICATE-----")
    end = openssl_out.find("-----END CERTIFICATE-----")
    if start == -1 or end == -1:
        return ""
    return openssl_out[start: end + len("-----END CERTIFICATE-----")]


# ── testssl.sh ────────────────────────────────────────────────────────────────

def _run_testssl(ip: str, port: int, runner: Runner, findings: Findings):
    findings.h4("testssl.sh")
    cmd = ["testssl.sh", "--color", "0", "--quiet", "--fast", f"{ip}:{port}"]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{ip}_{port}_testssl", timeout=300)

    flag_keywords = (
        "VULNERABLE", "HIGH", "MEDIUM", "NOT ok", "WARN",
        "BEAST", "POODLE", "SWEET32", "CRIME", "BREACH",
        "DROWN", "LOGJAM", "FREAK", "LUCKY13",
    )
    hits = [l.strip() for l in out.splitlines()
            if any(kw in l for kw in flag_keywords) and l.strip()]
    if hits:
        findings.bullet("**testssl findings:**")
        for line in hits[:20]:
            findings.bullet(f"  {line}")
    else:
        findings.bullet("testssl.sh: no critical findings")


# ── ADCS probe ────────────────────────────────────────────────────────────────

def _check_adcs(base_url: str, ip: str, runner: Runner, findings: Findings):
    found: list[tuple[str, str]] = []
    for path in _ADCS_PATHS:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        code = result.stdout.strip()
        if code in ("200", "301", "302", "401", "403"):
            found.append((path, code))

    if found:
        findings.h4("ADCS (AD Certificate Services)")
        findings.bullet("**ADCS web enrollment detected!**")
        for path, code in found:
            findings.bullet(f"  `{base_url}{path}` — HTTP {code}")
        findings.note(
            f"Check for ESC1-8 vulnerabilities: "
            f"`certipy find -u USER@DOMAIN -p PASS -dc-ip {ip} -vulnerable -stdout`"
        )


# ── WordPress ─────────────────────────────────────────────────────────────────

def _wpscan(base_url: str, runner: Runner, findings: Findings):
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "-o", "/dev/null",
         "-w", "%{http_code}", f"{base_url}/wp-login.php"],
        capture_output=True, text=True,
    )
    if result.stdout.strip() not in ("200", "302"):
        return

    findings.h4("WordPress (wpscan)")
    cmd = ["wpscan", "--url", base_url, "--enumerate", "p,u,t,cb,dbe",
           "--no-banner", "--disable-tls-checks"]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_wpscan", timeout=300)

    for line in out.splitlines():
        if any(kw in line for kw in ("[!]", "[+]", "vulnerability", "Vulnerability",
                                      "Username", "version")):
            findings.bullet(line.strip())


# ── CMS detection — Joomla + Drupal ─────────────────────────────────────────

def _check_cms(base_url: str, runner: Runner, findings: Findings, available: set[str]):
    # Joomla — admin panel at /administrator/
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "-o", "/dev/null",
         "-w", "%{http_code}", f"{base_url}/administrator/"],
        capture_output=True, text=True,
    )
    if r.stdout.strip() in ("200", "302", "301"):
        findings.h4("CMS: Joomla")
        findings.bullet(f"**Joomla admin panel:** `{base_url}/administrator/`")
        if "joomscan" in available:
            cmd = ["joomscan", "--url", base_url]
            findings.cmd(" ".join(cmd))
            out = runner.run(cmd, f"web_{_label(base_url)}_joomscan", timeout=300)
            for line in out.splitlines():
                if any(kw in line for kw in ("[++]", "[+]", "Vulnerable", "CVE", "version",
                                              "Admin", "Interesting")):
                    findings.bullet(line.strip())

    # Drupal — multiple indicators
    drupal_indicators = [
        ("/CHANGELOG.txt",           "Drupal CHANGELOG.txt"),
        ("/misc/drupal.js",          "Drupal JS asset"),
        ("/sites/default/settings.php", "Drupal settings.php"),
        ("/core/CHANGELOG.txt",      "Drupal 8+ CHANGELOG"),
    ]
    drupal_found = False
    for path, label in drupal_indicators:
        r2 = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        if r2.stdout.strip() == "200":
            if not drupal_found:
                findings.h4("CMS: Drupal")
                drupal_found = True
            findings.bullet(f"**{label}:** `{base_url}{path}`")

    if drupal_found and "droopescan" in available:
        cmd2 = ["droopescan", "scan", "drupal", "--url", base_url]
        findings.cmd(" ".join(cmd2))
        out2 = runner.run(cmd2, f"web_{_label(base_url)}_droopescan", timeout=300)
        for line in out2.splitlines():
            if line.strip() and not line.startswith("[*] Scanning"):
                findings.bullet(line.strip())


# ── Jenkins probe ─────────────────────────────────────────────────────────────

def _check_jenkins(base_url: str, runner: Runner, findings: Findings):
    """Probe for exposed Jenkins endpoints — /script console = unauthenticated RCE."""
    found: list[tuple[str, str, str]] = []
    for path, label in _JENKINS_PATHS:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        code = r.stdout.strip()
        if code in ("200", "302", "301", "403"):
            found.append((path, label, code))

    if not found:
        return

    # Confirm it's actually Jenkins, not a coincidental 200
    r_check = subprocess.run(
        ["curl", "-sk", "--max-time", "10", base_url],
        capture_output=True, text=True,
    )
    if "Jenkins" not in r_check.stdout and "hudson" not in r_check.stdout.lower():
        return

    findings.h4("Jenkins")
    for path, label, code in found:
        if code == "200" and path in ("/script", "/manage"):
            findings.bullet(f"**{label} ACCESSIBLE (HTTP {code}):** `{base_url}{path}`")
        else:
            findings.bullet(f"{label}: `{base_url}{path}` — HTTP {code}")

    if any(p == "/script" and c == "200" for p, _, c in found):
        findings.bullet("**CRITICAL: Script console accessible without auth — RCE**")
        findings.note(
            f"Execute OS commands: POST to `{base_url}/script` with "
            f"`script=println(['id'].execute().text)`"
        )
    if any(p == "/api/json" and c == "200" for p, _, c in found):
        findings.bullet("**Jenkins REST API accessible (no auth)** — enum jobs/builds")


# ── Directory bust ────────────────────────────────────────────────────────────

def _dir_bust(base_url: str, runner: Runner, findings: Findings):
    if not _exists(_WORDLIST_DIRS):
        findings.note(f"Wordlist missing: `{_WORDLIST_DIRS}` — skipping dir bust")
        return

    findings.h4("Directory Bust")
    cmd = [
        "ffuf", "-u", f"{base_url}/FUZZ",
        "-w", _WORDLIST_DIRS,
        "-e", _WEB_EXTENSIONS,
        "-fc", "404",
        "-t", "40",
        "-timeout", "10",
        "-ic",
    ]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_ffuf_dirs", timeout=600)
    _print_ffuf(out, findings)


# ── cewl custom wordlist generation ──────────────────────────────────────────

def _run_cewl(base_url: str, runner: Runner, findings: Findings) -> str | None:
    """
    Generate a site-specific wordlist by harvesting words from the target.
    Returns the path to the wordlist file, or None if cewl produced nothing.
    """
    wl_path = runner.ws.loot_dir / f"cewl_{_label(base_url)}.txt"
    cmd = ["cewl", base_url, "-d", "2", "-m", "5", "-w", str(wl_path),
           "--lowercase", "--with-numbers"]
    findings.cmd(" ".join(cmd))
    runner.run(cmd, f"web_{_label(base_url)}_cewl", timeout=120)

    if wl_path.exists() and wl_path.stat().st_size > 0:
        line_count = len(wl_path.read_text().splitlines())
        findings.bullet(f"cewl generated {line_count} custom words → `{wl_path}`")
        return str(wl_path)
    return None


def _dir_bust_cewl(base_url: str, wordlist: str, runner: Runner, findings: Findings):
    """Second dir bust pass using the cewl-generated wordlist."""
    findings.h4("Directory Bust (cewl wordlist)")
    cmd = [
        "ffuf", "-u", f"{base_url}/FUZZ",
        "-w", wordlist,
        "-e", _WEB_EXTENSIONS,
        "-fc", "404",
        "-t", "40",
        "-timeout", "10",
        "-ic",
    ]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_ffuf_cewl", timeout=300)
    _print_ffuf(out, findings)


# ── API endpoint discovery ────────────────────────────────────────────────────

def _api_bust(base_url: str, runner: Runner, findings: Findings):
    wl = _WORDLIST_API if _exists(_WORDLIST_API) else _WORDLIST_DIRS
    api_prefixes = ["/api", "/v1", "/v2", "/api/v1", "/api/v2", "/rest", "/graphql"]

    active_prefixes: list[str] = []
    for prefix in api_prefixes:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{prefix}"],
            capture_output=True, text=True,
        )
        if result.stdout.strip() not in ("404", "000", ""):
            active_prefixes.append(prefix)

    if not active_prefixes:
        return

    findings.h4("API Endpoints")
    for prefix in active_prefixes:
        cmd = [
            "ffuf", "-u", f"{base_url}{prefix}/FUZZ",
            "-w", wl,
            "-fc", "404",
            "-t", "40",
            "-timeout", "10",
            "-ic",
        ]
        findings.cmd(" ".join(cmd))
        out = runner.run(
            cmd,
            f"web_{_label(base_url)}_api{prefix.replace('/', '_')}",
            timeout=300,
        )
        results = _FFUF_RE.findall(out)
        if results:
            findings.bullet(f"**`{prefix}`** — {len(results)} endpoint(s):")
            for path, status, size in results:
                findings.bullet(f"  `{prefix}/{path}` — {status} ({size}b)")


# ── Vhost bust ────────────────────────────────────────────────────────────────

def _vhost_bust(ip: str, port: int, scheme: str, domain: str,
                runner: Runner, findings: Findings) -> list[str]:
    if not _exists(_WORDLIST_VHOST):
        findings.note(f"Wordlist missing: `{_WORDLIST_VHOST}` — skipping vhost bust")
        return []

    baseline = _vhost_baseline(ip, port, scheme)
    url = _build_url(scheme, ip, port)

    findings.h4("Vhost Bust")
    cmd = [
        "ffuf", "-u", url,
        "-H", f"Host: FUZZ.{domain}",
        "-w", _WORDLIST_VHOST,
        "-fc", "404",
        "-t", "40",
        "-timeout", "10",
        "-ic",
    ]
    if baseline > 0:
        cmd += ["-fs", str(baseline)]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(url)}_ffuf_vhosts", timeout=600)

    found: list[str] = []
    for match in _FFUF_RE.finditer(out):
        sub, status, size = match.group(1), match.group(2), match.group(3)
        full = f"{sub}.{domain}"
        findings.bullet(f"**`{full}`** — {status} ({size}b)")
        found.append(full)

    if not found:
        findings.bullet("No vhosts found.")

    return found


def _vhost_baseline(ip: str, port: int, scheme: str) -> int:
    url = _build_url(scheme, ip, port)
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10",
         "-o", "/dev/null", "-w", "%{size_download}",
         "-H", "Host: p0rtix-baseline-probe.invalid", url],
        capture_output=True, text=True,
    )
    try:
        return int(result.stdout.strip())
    except ValueError:
        return 0


# ── Crawl ─────────────────────────────────────────────────────────────────────

def _crawl(base_url: str, scope: Scope, runner: Runner, findings: Findings):
    findings.h4("Crawl")
    cmd = ["gospider", "-s", base_url, "-c", "5", "-d", "2",
           "--include-subs", "--no-redirect", "-q"]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_gospider", timeout=120)

    in_scope, out_of_scope = _parse_gospider(out, scope)

    if in_scope:
        findings.bullet(f"**In-scope URLs:** {len(in_scope)}")
        for url in sorted(set(in_scope))[:30]:
            findings.bullet(f"  {url}")
        if len(in_scope) > 30:
            findings.bullet(f"  … and {len(in_scope) - 30} more (see raw output)")

    if out_of_scope:
        findings.h4("External Links (not scanned)")
        for url in sorted(set(out_of_scope))[:20]:
            findings.bullet(url)


def _parse_gospider(output: str, scope: Scope) -> tuple[list[str], list[str]]:
    url_re = re.compile(
        r"\[(?:url|javascript|form|linkfinder|robots|sitemap)\]\s+-\s+\[.*?\]\s+-\s+\[(.+?)\]"
    )
    raw_urls = [m.group(1).strip() for m in url_re.finditer(output)]
    for line in output.splitlines():
        line = line.strip()
        if line.startswith("http") and line not in raw_urls:
            raw_urls.append(line)
    return scope.filter_urls(raw_urls)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_ffuf(output: str, findings: Findings):
    results = _FFUF_RE.findall(output)
    if not results:
        findings.bullet("No results.")
        return
    for path, status, size in results:
        findings.bullet(f"`/{path}` — {status} ({size}b)")


def _build_url(scheme: str, hostname: str, port: int) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


def _label(url: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", url.lower()).strip("_")[:40]


def _exists(path: str) -> bool:
    return Path(path).exists()
