"""Tests for the opt-in interactive shell handoff (Slice 6). The actual spawn is
mocked — CI never launches a child — so we cover invocation selection, the
RED/armed gating, and that the action calls the single spawn seam."""
from lib.engine import access
from lib.engine.action import Tier
from lib.engine.actions_builtin import build_registry
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler


class _FakeRunner:
    def __init__(self, ws):
        self.ws = ws


def _store(tmp_path):
    return FactStore("10.10.10.10", None, "shell-test", str(tmp_path))


# ── shell_command selection (pure) ────────────────────────────────────────────
def test_shell_command_prefers_admin_psexec(tmp_path):
    fs = _store(tmp_path)
    fs.set_discovered_domain("htb.local")
    fs.add_open_port("tcp", 445)
    fs.add_open_port("tcp", 5985)
    fs.add_admin_cred("administrator", "Passw0rd!")
    fs.add_valid_cred("svc", "s3rvice", "WINRM")

    cmd = access.shell_command(fs, "10.10.10.10")
    assert cmd[0] == "impacket-psexec"
    assert cmd[1] == "htb.local/administrator:Passw0rd!@10.10.10.10"


def test_shell_command_winrm_when_no_admin(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    cmd = access.shell_command(fs, "10.10.10.10")
    assert cmd == ["evil-winrm", "-i", "10.10.10.10",
                   "-u", "svc-alfresco", "-p", "s3rvice"]


def test_shell_command_none_without_shellable_service(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 445)                 # SMB but only a non-admin cred
    fs.add_valid_cred("svc-alfresco", "s3rvice", "SMB")
    assert access.shell_command(fs, "10.10.10.10") is None


def test_shell_command_prefers_user_over_machine(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("EXCH01$", "machinepw", "WINRM")
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")
    cmd = access.shell_command(fs, "10.10.10.10")
    assert "svc-alfresco" in cmd


# ── access.shell action: RED, armed-only, invokes the spawn seam ──────────────
def _wire(tmp_path, dial=0):
    fs = _store(tmp_path)
    posture = Posture(dial=dial)
    reg = build_registry()
    sched = Scheduler(reg, fs, posture, ip="10.10.10.10",
                      runner=_FakeRunner(fs), tools=set())
    return fs, posture, reg, sched


def test_access_shell_is_manual_only_yellow(tmp_path):
    fs, posture, reg, sched = _wire(tmp_path, dial=0)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    shell = reg.get("access.shell")
    assert shell.tier is Tier.YELLOW and shell.manual_only
    # available for an explicit run at YELLOW (no arming needed)
    posture.raise_to(Tier.YELLOW)
    assert "access.shell" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}


def test_access_shell_not_swept_by_run_all_or_group(tmp_path, monkeypatch):
    launched = {}
    monkeypatch.setattr(access, "launch_shell",
                        lambda cmd: launched.setdefault("cmd", cmd) or 0)
    fs, posture, reg, sched = _wire(tmp_path, dial=0)
    posture.raise_to(Tier.YELLOW)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    sched.run_all_at_or_below()        # bulk run must NOT spawn a shell
    sched.run_group("access")          # nor a group run
    assert "cmd" not in launched

    sched.run_action("access.shell")   # explicit run does
    assert launched["cmd"][0] == "evil-winrm"


def test_shell_command_ssh_when_only_22(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_valid_cred("root", "toor", "SSH")
    cmd = access.shell_command(fs, "10.10.10.10")
    assert cmd[0] == "sshpass" and "root@10.10.10.10" in cmd


def _capture_call(seen):
    def _call(argv, **kw):
        seen["argv"] = argv
        return 0
    return _call


def test_local_shell_uses_seam(tmp_path, monkeypatch):
    monkeypatch.delenv("TMUX", raising=False)        # force the blocking path
    monkeypatch.setattr(access, "_recover_tmux_env", lambda: None)
    calls = {}
    monkeypatch.setattr(access.subprocess, "call",
                        lambda argv, cwd=None: calls.update(argv=argv, cwd=cwd) or 0)
    access.local_shell(str(tmp_path))
    assert calls["cwd"] == str(tmp_path)


def test_launch_shell_uses_tmux_window_when_in_tmux(tmp_path, monkeypatch):
    seen = {}
    monkeypatch.setenv("TMUX", "/tmp/tmux-1000/default,1234,0")
    monkeypatch.setattr(access.subprocess, "call", _capture_call(seen))
    rc = access.launch_shell(["evil-winrm", "-i", "10.0.0.1", "-u", "a", "-p", "b"])
    assert rc == 0
    assert seen["argv"][:2] == ["tmux", "new-window"]
    assert any("evil-winrm" in part for part in seen["argv"])


def test_launch_shell_blocks_without_tmux(tmp_path, monkeypatch):
    monkeypatch.delenv("TMUX", raising=False)
    monkeypatch.setattr(access, "_recover_tmux_env", lambda: None)
    seen = {}
    monkeypatch.setattr(access.subprocess, "call", _capture_call(seen))
    access.launch_shell(["evil-winrm", "-i", "10.0.0.1"])
    assert seen["argv"][0] == "evil-winrm"      # direct spawn, not tmux


def test_shell_command_winrm_ssl_5986(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 5986)                    # WinRM over HTTPS, no 5985
    fs.add_valid_cred("legacyy", "pw!", "WINRM")
    cmd = access.shell_command(fs, "10.10.10.10")
    assert cmd[0] == "evil-winrm" and "-S" in cmd    # SSL flag


def test_can_shell_only_when_buildable(tmp_path):
    from lib.engine.actions_builtin import _can_shell
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 445)
    fs.add_valid_cred("legacyy", "pw!", "SMB")       # non-admin + only SMB
    assert not _can_shell(fs)                         # no shell buildable → not advertised
    fs.add_open_port("tcp", 5986)
    assert _can_shell(fs)                             # WinRM now → buildable
