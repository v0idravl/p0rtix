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


def test_access_shell_is_red_and_locked_until_armed(tmp_path):
    fs, posture, reg, sched = _wire(tmp_path, dial=0)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    shell = reg.get("access.shell")
    assert shell.tier is Tier.RED
    # RED locked at dial 0 → not available even with a cred+service
    posture.raise_to(Tier.YELLOW)
    assert "access.shell" not in {a.name for a, _ in reg.available(fs, posture, sched.tried)}

    # arm RED → available
    posture.arm_dangerous()
    posture.raise_to(Tier.RED)
    assert "access.shell" in {a.name for a, _ in reg.available(fs, posture, sched.tried)}


def test_access_shell_invokes_launch(tmp_path, monkeypatch):
    launched = {}
    monkeypatch.setattr(access, "launch_shell",
                        lambda cmd: launched.setdefault("cmd", cmd) or 0)
    fs, posture, reg, sched = _wire(tmp_path, dial=7)   # dial 7 arms RED
    posture.raise_to(Tier.RED)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    sched.run_action("access.shell")
    assert launched["cmd"][0] == "evil-winrm"


def test_shell_command_ssh_when_only_22(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_valid_cred("root", "toor", "SSH")
    cmd = access.shell_command(fs, "10.10.10.10")
    assert cmd[0] == "sshpass" and "root@10.10.10.10" in cmd


def test_local_shell_uses_seam(tmp_path, monkeypatch):
    calls = {}
    monkeypatch.setattr(access.subprocess, "call",
                        lambda argv, cwd=None: calls.update(argv=argv, cwd=cwd) or 0)
    access.local_shell(str(tmp_path))
    assert calls["cwd"] == str(tmp_path)
