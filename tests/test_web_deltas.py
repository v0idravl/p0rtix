"""Coverage for the newer pure-parsing/logic deltas in lib/web.py — the artifact
secret scanner, broadened JS-endpoint extraction, WordPress author enum parsing,
and the Host-header / vhost-promotion helpers. All fakes; no real network.

These exercise the parsing/recording seams directly: the network-bound functions
(`_scrape_js`, `_follow_js_endpoints`, `_wp_author_enum`) shell out via
subprocess/curl, so we test their REGEX/parse logic and route `subprocess.run`
through a monkeypatched fake where the function itself is driven."""
import base64
import io
import subprocess
import zipfile

from lib import web
from lib.engine.facts import FactStore


# ── fakes ──────────────────────────────────────────────────────────────────────

class _FakeFindings:
    """Accepts any findings call (h2/h3/h4/bullet/cmd/note/add_summary/code_block/…)
    and records (method, args) so a test can assert on them if it wants."""
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def _rec(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return None
        return _rec


class _RecorderWS:
    """A minimal workspace recorder exposing the fact-mutator seams web.py uses."""
    def __init__(self):
        self.creds = []
        self.users = []
        self.hostnames = []
        self.domains = []

    def add_cred(self, text):
        self.creds.append(text)

    def add_user(self, username):
        self.users.append(username)

    def add_hostname(self, fqdn):
        self.hostnames.append(fqdn)

    def set_discovered_domain(self, domain):
        self.domains.append(domain)


class _FakeRunner:
    """A runner with a .ws (recorder or real FactStore) and a no-network .run()."""
    def __init__(self, ws):
        self.ws = ws

    def run(self, cmd, label, timeout=None):
        return ""


def _real_runner(tmp_path):
    fs = FactStore("10.10.10.10", None, "webdeltas", str(tmp_path))
    return _FakeRunner(fs), fs


# ── 1. artifact secret scan ─────────────────────────────────────────────────────

def test_scan_artifact_bytes_zip_finds_props_and_class_strings(tmp_path):
    runner, fs = _real_runner(tmp_path)
    findings = _FakeFindings()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.properties", "db.password=Sup3rS3cret!\nuser=admin\n")
        # a compiled .class member: the cred survives as an ASCII run inside binary
        zf.writestr("Core.class",
                    b"\xca\xfe\xba\xbe\x00\x00password=H4rdcoded\x00\x01\x02")
    zipbytes = buf.getvalue()

    n = web._scan_artifact_bytes("http://x/app.jar", zipbytes, runner, findings)
    assert n >= 2
    creds = fs.snapshot()["creds"]
    assert "Sup3rS3cret!" in creds
    assert "H4rdcoded" in creds


def test_ascii_strings_pulls_printable_runs():
    s = web._ascii_strings(b"AB\x00password=hunter2\x01CD")
    assert "password=hunter2" in s


def test_scan_artifact_bytes_plain_blob_records_creds(tmp_path):
    runner, fs = _real_runner(tmp_path)
    findings = _FakeFindings()
    blob = b"username=root\npassword=toor\n"

    n = web._scan_artifact_bytes("http://x/db.bak", blob, runner, findings)
    assert n >= 1
    creds = fs.snapshot()["creds"]
    assert "toor" in creds
    assert "root" in creds


def test_scan_artifact_bytes_captures_jdbc(tmp_path):
    runner, fs = _real_runner(tmp_path)
    findings = _FakeFindings()
    blob = b"jdbc:mysql://app:Passw0rd@db/foo\n"

    n = web._scan_artifact_bytes("http://x/conf.txt", blob, runner, findings)
    assert n >= 1
    # the whole JDBC URL is itself the secret — assert the JDBC branch fired
    summaries = [a[0] for (m, a, _k) in findings.calls if m == "add_summary" and a]
    assert any("JDBC" in str(s) for s in summaries)


# ── 2. JS endpoint following — regex extraction ─────────────────────────────────

def _js_endpoints(body):
    out = []
    for rx in web._JS_ENDPOINT_RES:
        for m in rx.findall(body):
            m = m.strip()
            if m and m not in out:
                out.append(m)
    return out


def test_js_endpoint_regexes_capture_ajax_and_absolute_refs():
    body = (
        "$.get('scan.php');\n"
        'fetch("/api/data");\n'
        "axios.post('upload.php', payload);\n"
        'var u = "/admin/secret";\n'
    )
    eps = _js_endpoints(body)
    assert "scan.php" in eps
    assert "/api/data" in eps
    assert "upload.php" in eps
    assert "/admin/secret" in eps


def test_js_endpoint_relative_ref_is_captured_now():
    # the OLD regex only matched leading-slash absolute paths; a bare relative
    # `scan.php` (no slash) must now be captured too.
    eps = _js_endpoints("$.get('scan.php');")
    assert "scan.php" in eps


def test_follow_js_endpoints_empty_is_noop(tmp_path):
    runner, _fs = _real_runner(tmp_path)
    findings = _FakeFindings()
    # empty input returns without error (no curl, no findings)
    assert web._follow_js_endpoints(set(), runner, findings) is None


# ── 3. WordPress author enum — parsing via monkeypatched subprocess.run ──────────

def test_wp_author_enum_parses_rest_and_author_redirect(monkeypatch, tmp_path):
    runner, fs = _real_runner(tmp_path)
    findings = _FakeFindings()

    def fake_run(cmd, *args, **kwargs):
        joined = " ".join(cmd)
        # REST users endpoint GET
        if "wp-json/wp/v2/users" in joined:
            stdout = '[{"slug":"admin","name":"Administrator"},{"slug":"editor"}]'
        # ?author=N HEAD probes — emit a Location for author=3 only
        elif "?author=3" in joined:
            stdout = "HTTP/1.1 301 Moved\r\nLocation: http://x/author/john/\r\n"
        elif "?author=" in joined:
            stdout = "HTTP/1.1 200 OK\r\n"
        else:
            stdout = ""
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(web.subprocess, "run", fake_run)

    users = web._wp_author_enum("http://x", runner, findings)
    assert "admin" in users
    assert "editor" in users
    assert "john" in users
    # _record_user pushed each into the fact store
    fact_users = fs.snapshot()["users"]
    assert {"admin", "editor", "john"} <= set(fact_users)


# ── 3b. Catch-all redirect detection + signature-probe filtering ─────────────────

def test_catchall_redirect_detects_blanket_30x(monkeypatch):
    # A bogus path that still 302s → vhost-only routing (the Analytics case).
    def fake_run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0,
            stdout="302 http://analytical.htb/", stderr="")
    monkeypatch.setattr(web.subprocess, "run", fake_run)

    assert web._catchall_redirect("http://10.129.229.224") == ("302", "http://analytical.htb/")


def test_catchall_redirect_none_when_bogus_path_404s(monkeypatch):
    def fake_run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, 0, stdout="404 ", stderr="")
    monkeypatch.setattr(web.subprocess, "run", fake_run)

    assert web._catchall_redirect("http://10.129.229.224") is None


def test_probe_code_filters_catchall_but_keeps_real_hits(monkeypatch):
    catchall = ("302", "http://analytical.htb/")

    def fake_run(cmd, *args, **kwargs):
        url = cmd[-1]
        # The blanket vhost redirect — same Location as the catch-all baseline.
        if url.endswith("/certsrv"):
            stdout = "302 http://analytical.htb/"
        # A real endpoint that 302s somewhere ELSE (e.g. app login).
        elif url.endswith("/manager/html"):
            stdout = "401 "
        elif url.endswith("/app"):
            stdout = "302 http://10.129.229.224/app/login"
        else:
            stdout = "404 "
        return subprocess.CompletedProcess(cmd, 0, stdout=stdout, stderr="")
    monkeypatch.setattr(web.subprocess, "run", fake_run)

    # Catch-all redirect → filtered to None (no false ADCS hit).
    assert web._probe_code("http://10.129.229.224/certsrv", None, catchall) is None
    # Real 401 → kept.
    assert web._probe_code("http://10.129.229.224/manager/html", None, catchall) == "401"
    # Real 302 to a different location → kept (not the catch-all).
    assert web._probe_code("http://10.129.229.224/app", None, catchall) == "302"
    # Without a catch-all baseline, the old behavior holds (30x reported).
    assert web._probe_code("http://10.129.229.224/certsrv", None, None) == "302"


# ── 4. Host header + vhost promotion ────────────────────────────────────────────

def test_hh_builds_host_header_args():
    assert web._hh("blocky.htb") == ["-H", "Host: blocky.htb"]
    assert web._hh(None) == []


def test_promote_vhost_fqdn_sets_domain_and_hostname():
    ws = _RecorderWS()
    web._promote_vhost(_FakeRunner(ws), "blocky.htb")
    assert "blocky.htb" in ws.hostnames
    assert "blocky.htb" in ws.domains


def test_promote_vhost_bare_label_only_hostname():
    ws = _RecorderWS()
    web._promote_vhost(_FakeRunner(ws), "bare")
    assert "bare" in ws.hostnames
    # no dot → not promoted to the domain fact
    assert ws.domains == []


def test_promote_vhost_real_factstore(tmp_path):
    runner, fs = _real_runner(tmp_path)
    web._promote_vhost(runner, "blocky.htb")
    snap = fs.snapshot()
    assert "blocky.htb" in snap["hostnames"]
    assert snap["domain"] == "blocky.htb"


# ── 5. XSS-to-privilege recon tells (cookies + forms) ────────────────────────────

def test_cookie_role_tell_base64_role_value():
    # Headless: a non-HttpOnly is_admin cookie whose value base64-decodes to "user"
    b64 = base64.b64encode(b"user").decode()
    tell = web._cookie_role_tell(f"Set-Cookie: is_admin={b64}")
    assert tell and "decodes to `user`" in tell


def test_cookie_role_tell_plain_role_value():
    tell = web._cookie_role_tell("Set-Cookie: role=admin; Path=/")
    assert tell and "role value" in tell


def test_cookie_role_tell_name_hint_only():
    # name looks like a privilege flag even if the value isn't a known role token
    tell = web._cookie_role_tell("Set-Cookie: usertype=2; Path=/")
    assert tell and "role/privilege flag" in tell


def test_cookie_role_tell_ignores_session_blob():
    # an ordinary long session id is not a role tell (avoids false positives)
    blob = "PHPSESSID=" + "a1b2c3d4" * 6
    assert web._cookie_role_tell(f"Set-Cookie: {blob}; HttpOnly") is None


def test_parse_headers_emits_privilege_tell_for_jsreadable_role_cookie():
    findings = _FakeFindings()
    raw = ("HTTP/1.1 200 OK\r\n"
           "Set-Cookie: is_admin=" + base64.b64encode(b"user").decode() + "; Path=/\r\n")
    web._parse_interesting_headers(raw, findings)
    notes = [a[0] for nm, a, _ in findings.calls if nm == "note"]
    assert any("Privilege tell" in n and "no HttpOnly" in n for n in notes)


class _HtmlRunner:
    """Runner whose .run returns canned HTML (for the landing-page form check)."""
    def __init__(self, html):
        self.html = html
        self.ws = None

    def run(self, cmd, label, timeout=None):
        return self.html


def test_check_forms_flags_freetext_contact_form():
    findings = _FakeFindings()
    html = ('<html><body><form method="post" action="/support">'
            '<input type="text" name="email">'
            '<textarea name="message"></textarea>'
            '</form></body></html>')
    web._check_forms("http://10.10.10.10", _HtmlRunner(html), findings)
    bullets = [a[0] for nm, a, _ in findings.calls if nm == "bullet"]
    notes = [a[0] for nm, a, _ in findings.calls if nm == "note"]
    assert any("/support" in b for b in bullets)
    assert any("stored/blind-XSS" in n for n in notes)


def test_check_forms_noop_when_no_form():
    findings = _FakeFindings()
    web._check_forms("http://10.10.10.10", _HtmlRunner("<html>no forms</html>"), findings)
    assert findings.calls == []


# ── 6. Spring Boot Actuator probe (CozyHosting delta) ────────────────────────────

import json as _json


def test_parse_actuator_sessions_principal_map():
    # {"<sessionid>": {"principal": "<user>"}} — the classic CozyHosting shape.
    body = _json.dumps({"abcd-1234": {"principal": "kanderson"},
                        "ef01-5678": {"principal": "admin"}})
    assert web._parse_actuator_sessions(body) == ["kanderson", "admin"]


def test_parse_actuator_sessions_list_shape():
    body = _json.dumps({"sessions": [{"principalName": "josh"},
                                     {"principalName": "josh"},  # dup collapses
                                     {"principalName": "root"}]})
    assert web._parse_actuator_sessions(body) == ["josh", "root"]


def test_parse_actuator_sessions_regex_fallback():
    # Non-JSON / flattened body still yields usernames via the regex fallback.
    body = 'garbage "username":"svc-web" more "principal":"dba"'
    assert web._parse_actuator_sessions(body) == ["svc-web", "dba"]


def test_parse_actuator_sessions_empty():
    assert web._parse_actuator_sessions("not json at all") == []


def test_spring_detected_via_whitelabel_error_page(monkeypatch):
    def fake_run(cmd, *a, **k):
        url = cmd[-1]
        body = "<html><body>Whitelabel Error Page</body></html>" if url.endswith("/error") else ""
        return subprocess.CompletedProcess(cmd, 0, stdout=body, stderr="")
    monkeypatch.setattr(web.subprocess, "run", fake_run)
    assert web._spring_detected("http://10.10.10.10", {}, None) is True


def test_spring_detected_false_for_plain_app(monkeypatch):
    def fake_run(cmd, *a, **k):
        return subprocess.CompletedProcess(cmd, 0, stdout="<html>nginx welcome</html>", stderr="")
    monkeypatch.setattr(web.subprocess, "run", fake_run)
    assert web._spring_detected("http://10.10.10.10", {"server": "nginx"}, None) is False


def test_check_spring_actuator_leaks_sessions_to_users(monkeypatch, tmp_path):
    runner, fs = _real_runner(tmp_path)
    findings = _FakeFindings()

    def fake_run(cmd, *a, **k):
        url = cmd[-1]
        has_w = "-w" in cmd
        if has_w:  # _probe_code: "<code> <redirect_url>"
            if url.endswith("/actuator") or url.endswith("/actuator/sessions") \
               or url.endswith("/actuator/env"):
                return subprocess.CompletedProcess(cmd, 0, stdout="200 ", stderr="")
            return subprocess.CompletedProcess(cmd, 0, stdout="404 ", stderr="")
        # body fetches (no -w): detection + sessions body
        if url.endswith("/error"):
            return subprocess.CompletedProcess(cmd, 0, stdout="Whitelabel Error Page", stderr="")
        if url.endswith("/actuator/sessions"):
            return subprocess.CompletedProcess(
                cmd, 0, stdout=_json.dumps({"s1": {"principal": "kanderson"}}), stderr="")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(web.subprocess, "run", fake_run)
    web._check_spring_actuator("http://10.10.10.10", {}, runner, findings)

    # the leaked session username is promoted to a user fact (reuse spray feed)
    assert "kanderson" in fs.snapshot()["users"]
    summaries = [a[0] for nm, a, _ in findings.calls if nm == "add_summary"]
    assert any("Actuator exposed" in str(s) for s in summaries)
    assert any("session hijack" in str(s) for s in summaries)


def test_check_spring_actuator_noop_when_not_spring(monkeypatch, tmp_path):
    runner, _fs = _real_runner(tmp_path)
    findings = _FakeFindings()

    def fake_run(cmd, *a, **k):
        return subprocess.CompletedProcess(cmd, 0, stdout="plain html", stderr="")
    monkeypatch.setattr(web.subprocess, "run", fake_run)

    web._check_spring_actuator("http://10.10.10.10", {"server": "nginx"}, runner, findings)
    assert findings.calls == []
