from types import SimpleNamespace

from lib.findings import Findings, ServiceBuffer, set_verbose
from lib.runner import Runner
from lib.workspace import Workspace


def test_findings_generates_summary_notices_and_service_content(tmp_path):
    set_verbose(False)
    findings_path = tmp_path / "findings.md"
    findings = Findings(findings_path, "192.0.2.10", "example.internal")

    buf = ServiceBuffer(445, "tcp")
    buf.h3("TCP 445 — SMB")
    buf.cmd("nmap --script smb-enum-shares -p 445 192.0.2.10")
    buf.bullet("Shares: IPC$ (NO ACCESS), Public (READ)")
    buf.note("optional SMB tool missing; skipped")
    buf.add_summary("Readable SMB share: `Public`")

    findings.h2("Service Findings")
    findings.flush_service_buffer(buf)
    findings.finalize()

    content = findings_path.read_text()

    assert "# p0rtix — 192.0.2.10" in content
    assert "Domain     example.internal" in content
    assert "TCP 445 — SMB" in content
    assert "> `nmap --script smb-enum-shares -p 445 192.0.2.10`" in content
    assert "Readable SMB share: `Public`" in content
    assert "## Key Findings" in content
    assert "## Notices" in content
    assert "TCP 445: optional SMB tool missing; skipped" in content


def test_runner_uses_argument_list_and_records_quoted_command(monkeypatch, tmp_path):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return SimpleNamespace(stdout="ok\n", stderr="", returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)

    ws = Workspace("192.0.2.10", None, "runner-test", str(tmp_path))
    runner = Runner(ws)
    output = runner.run(["printf", "hello; rm -rf /"], "safe_command")

    assert output == "ok\n"
    assert calls == [
        (["printf", "hello; rm -rf /"], {"capture_output": True, "text": True, "timeout": 300, "cwd": None})
    ]

    raw_files = list(ws.raw_dir.glob("*_safe_command.txt"))
    assert len(raw_files) == 1
    raw_content = raw_files[0].read_text()
    assert "# Command : printf 'hello; rm -rf /'" in raw_content
    assert "ok" in raw_content
