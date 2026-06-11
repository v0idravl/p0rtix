"""Mocked tests for the nmap carve-outs. No real nmap runs: a fake runner writes
the XML the parser expects, keyed by the -oA label."""
from lib.nmap import discover_tcp_open, version_detect
from lib.workspace import Workspace

_TCP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/></port>
      <port protocol="tcp" portid="445"><state state="open"/>
        <service name="microsoft-ds"/></port>
      <port protocol="tcp" portid="9999"><state state="closed"/></port>
    </ports>
  </host>
</nmaprun>"""


class _FakeRunner:
    """Stands in for Runner: run_live writes the canned XML for the -oA label."""

    def __init__(self, ws, xml_by_label):
        self.ws = ws
        self._xml = xml_by_label
        self.calls = []

    def run_live(self, cmd, label, timeout=900):
        self.calls.append((cmd, label))
        if label in self._xml:
            (self.ws.raw_dir / f"{label}.xml").write_text(self._xml[label])
        return ""


def test_discover_tcp_open_returns_open_ports_only(tmp_path):
    ws = Workspace("192.0.2.10", None, "nmap-test", str(tmp_path))
    runner = _FakeRunner(ws, {"01_full_tcp": _TCP_XML})

    ports = discover_tcp_open("192.0.2.10", runner, ws)

    assert ports == [22, 445]            # closed 9999 excluded
    # open-only sweep must NOT request version detection
    cmd = runner.calls[0][0]
    assert "-sV" not in cmd
    assert "-p-" in cmd and "--open" in cmd


def test_version_detect_runs_sV_and_parses_services(tmp_path):
    ws = Workspace("192.0.2.10", None, "nmap-test", str(tmp_path))
    runner = _FakeRunner(ws, {"04_tcp_services": _TCP_XML})

    services = version_detect("192.0.2.10", [22, 445], runner, ws)

    by_port = {s.port: s for s in services}
    assert set(by_port) == {22, 445}
    assert by_port[22].version == "OpenSSH 8.9p1"
    assert "-sV" in runner.calls[0][0]


def test_version_detect_noop_on_empty_ports(tmp_path):
    ws = Workspace("192.0.2.10", None, "nmap-test", str(tmp_path))
    runner = _FakeRunner(ws, {})
    assert version_detect("192.0.2.10", [], runner, ws) == []
    assert runner.calls == []            # no nmap invoked
