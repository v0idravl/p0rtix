"""Tests for non-interactive command execution (access.exec).

p0rtix no longer drops interactive shells. The furthest it goes is running ONE
command via a known credential and capturing stdout. These cover invocation
selection (pure), the YELLOW/manual-only gating, that a bulk run never sweeps it,
and that an explicit run with a command actually executes through the Runner."""
from lib.engine import access
from lib.engine.action import Tier
from lib.engine.actions_builtin import build_registry, _can_exec
from lib.engine.facts import FactStore
from lib.engine.posture import Posture
from lib.engine.scheduler import Scheduler


class _FakeRunner:
    """Records the last argv and returns canned stdout (no real subprocess)."""

    def __init__(self, ws, out="nt authority\\system"):
        self.ws = ws
        self.fresh = False
        self.out = out
        self.calls = []

    def run(self, cmd, label, timeout=None):
        self.calls.append((cmd, label))
        return self.out


def _store(tmp_path):
    return FactStore("10.10.10.10", None, "exec-test", str(tmp_path))


# ── exec_command selection (pure) ─────────────────────────────────────────────
def test_exec_command_prefers_admin_smb(tmp_path):
    fs = _store(tmp_path)
    fs.set_discovered_domain("htb.local")
    fs.add_open_port("tcp", 445)
    fs.add_open_port("tcp", 5985)
    fs.add_admin_cred("administrator", "Passw0rd!")
    fs.add_valid_cred("svc", "s3rvice", "WINRM")

    cmd = access.exec_command(fs, "10.10.10.10", "whoami")
    assert cmd[:3] == ["nxc", "smb", "10.10.10.10"]
    assert cmd[-2:] == ["-x", "whoami"]
    assert "-d" in cmd and "htb.local" in cmd


def test_exec_command_winrm_when_no_admin(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    cmd = access.exec_command(fs, "10.10.10.10", "hostname")
    assert cmd[:2] == ["nxc", "winrm"]
    assert cmd[-2:] == ["-x", "hostname"]


def test_exec_command_winrm_ssl_5986(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 5986)                    # WinRM over HTTPS, no 5985
    fs.add_valid_cred("legacyy", "pw!", "WINRM")
    cmd = access.exec_command(fs, "10.10.10.10", "whoami")
    assert cmd[:2] == ["nxc", "winrm"] and "--ssl" in cmd


def test_exec_command_ssh_when_only_22(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 22)
    fs.add_valid_cred("root", "toor", "SSH")
    cmd = access.exec_command(fs, "10.10.10.10", "id")
    assert cmd[0] == "sshpass" and cmd[-2:] == ["root@10.10.10.10", "id"]


def test_exec_command_none_without_runnable_service(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 445)                 # SMB but only a non-admin cred
    fs.add_valid_cred("svc-alfresco", "s3rvice", "SMB")
    assert access.exec_command(fs, "10.10.10.10", "whoami") is None


def test_exec_command_prefers_user_over_machine(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("EXCH01$", "machinepw", "WINRM")
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")
    cmd = access.exec_command(fs, "10.10.10.10", "whoami")
    assert "svc-alfresco" in cmd and "EXCH01$" not in cmd


# ── access.exec action: YELLOW, manual-only, executes via the runner ──────────
def _wire(tmp_path, dial=0, runner=None):
    fs = _store(tmp_path)
    posture = Posture(dial=dial)
    reg = build_registry()
    runner = runner or _FakeRunner(fs)
    sched = Scheduler(reg, fs, posture, ip="10.10.10.10",
                      runner=runner, tools={"nxc"})
    return fs, posture, reg, sched, runner


def test_access_exec_is_manual_only_yellow(tmp_path):
    fs, posture, reg, sched, _ = _wire(tmp_path)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    exec_action = reg.get("access.exec")
    assert exec_action.tier is Tier.YELLOW and exec_action.manual_only
    posture.raise_to(Tier.YELLOW)
    assert "access.exec" in {a.name for a, _ in reg.available(fs, posture, sched.tried, {"nxc"})}


def test_access_exec_not_swept_by_run_all_or_group(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path)
    posture.raise_to(Tier.YELLOW)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    sched.run_all_at_or_below()        # bulk run must NOT exec
    sched.run_group("access")          # nor a group run
    assert runner.calls == []

    # explicit run with a command does execute
    sched.run_action("access.exec", extra_args={"command": "whoami"})
    assert runner.calls and runner.calls[-1][0][-2:] == ["-x", "whoami"]


def test_access_exec_without_command_is_a_noop(tmp_path):
    fs, posture, reg, sched, runner = _wire(tmp_path)
    posture.raise_to(Tier.YELLOW)
    fs.add_open_port("tcp", 5985)
    fs.add_valid_cred("svc-alfresco", "s3rvice", "WINRM")

    sched.run_action("access.exec")    # no command supplied
    assert runner.calls == []          # nothing executed


def test_can_exec_only_when_runnable(tmp_path):
    fs = _store(tmp_path)
    fs.add_open_port("tcp", 445)
    fs.add_valid_cred("legacyy", "pw!", "SMB")       # non-admin + only SMB
    assert not _can_exec(fs)                          # nothing runnable → not advertised
    fs.add_open_port("tcp", 5986)
    assert _can_exec(fs)                              # WinRM now → runnable
