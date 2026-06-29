import os
import shlex
import subprocess
from datetime import datetime
from pathlib import Path

from lib.logger import get_logger
from lib.workspace import Workspace

_log = get_logger()

# Written by sliver-mcp start_socks; deleted by stop_socks.
# When present, nmap scans route through the SOCKS proxy.
_PROXYCHAINS_CONF = Path.home() / ".cache" / "dagar-proxychains.conf"


class Runner:
    """
    Executes external tools and persists their output.

    Two modes:
      run()      — captures stdout/stderr silently (for parallel service tools)
      run_live() — streams output to the terminal in real time (for slow nmap scans)

    Every call saves a timestamped raw file under workspace/raw/ with the exact
    command prepended so results are always reproducible.
    """

    def __init__(self, ws: Workspace):
        self._ws = ws
        # When True, run() bypasses the cached raw file and re-executes, writing
        # back to the same file. The engine flips this on for an explicit re-run.
        self.fresh = False

    @property
    def ws(self) -> Workspace:
        return self._ws

    def proxy_cmd(self, cmd: list[str]) -> list[str]:
        """Wrap cmd with proxychains if a dagar SOCKS proxy is active.

        SYN scans (-sS) require raw sockets and don't work through SOCKS, so they
        are downgraded to TCP-connect (-sT) automatically.
        """
        if not _PROXYCHAINS_CONF.exists():
            return cmd
        adapted = ["-sT" if a == "-sS" else a for a in cmd]
        return ["proxychains", "-q", "-f", str(_PROXYCHAINS_CONF)] + adapted

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self, cmd: list[str], label: str, timeout: int = 300,
            cwd: str | None = None, env: dict[str, str] | None = None) -> str:
        """
        Run a command, capture output, save to raw/, return stdout as string.
        On resume (raw file already exists from a prior scan), returns cached output.
        Failures are recorded in the raw file but do not raise exceptions.
        cwd: working directory for the subprocess (default: inherit current).
        env: extra environment variables, merged over the inherited environment.
        """
        existing = next(self._ws.raw_dir.glob(f"*_{label}.txt"), None)
        if existing and not self.fresh:
            cached = existing.read_text()
            sep = "# " + "=" * 60 + "\n\n"
            return cached.split(sep, 1)[-1] if sep in cached else cached

        # fresh re-run overwrites the existing raw file in place; otherwise a new
        # numbered file is created.
        raw_path = existing if (existing and self.fresh) \
            else self._ws.raw_dir / f"{self._ws.next_raw_label(label)}.txt"
        cmd_str = shlex.join(cmd)
        _log.debug("RUN [%s]: %s", label, cmd_str)

        run_env = {**os.environ, **env} if env else None
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd,
                env=run_env,
            )
            output = result.stdout
            if result.stderr.strip():
                output += f"\n[stderr]\n{result.stderr}"
                # Only surface stderr as a warning when the tool actually failed
                # (non-zero exit). Many tools (certipy, bloodhound, dnsrecon,
                # searchsploit) print banners/INFO to stderr while succeeding —
                # logging those as warnings makes errors.log look alarming for no
                # reason. The full stderr is preserved in the raw file regardless.
                if result.returncode != 0:
                    stderr_preview = result.stderr.strip().splitlines()[0][:200]
                    _log.warning("STDERR [%s] (exit %d): %s",
                                 label, result.returncode, stderr_preview)
        except subprocess.TimeoutExpired as e:
            def _s(b: str | bytes | None) -> str:
                if b is None:
                    return ""
                return b if isinstance(b, str) else b.decode("utf-8", errors="replace")
            partial = _s(e.stdout) + _s(e.stderr)
            output = f"[TIMEOUT after {timeout}s — partial output below]\n{partial}"
            _log.error("TIMEOUT [%s] after %ds: %s", label, timeout, cmd_str)
        except FileNotFoundError:
            output = f"[ERROR — command not found: {cmd[0]}]\n"
            _log.error("NOT FOUND [%s]: %s", label, cmd[0])

        self._save(raw_path, cmd_str, output)
        return output

    def run_live(self, cmd: list[str], label: str, timeout: int = 900) -> str:
        """
        Run a command with live terminal output (line by line).
        Also saves full output to raw/ for reference.
        Used for nmap discovery phases where the operator wants to see progress.
        """
        # nmap -oA creates its own output files, so this log is supplemental
        raw_path = self._ws.raw_dir / f"{label}.log"
        cmd_str = shlex.join(cmd)

        lines: list[str] = []
        try:
            with subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            ) as proc:
                assert proc.stdout  # always set when PIPE
                for line in proc.stdout:
                    print(line, end="", flush=True)
                    lines.append(line)
                proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timeout_msg = f"\n[TIMEOUT — exceeded {timeout}s]\n"
            print(timeout_msg)
            lines.append(timeout_msg)
        except FileNotFoundError:
            err = f"[ERROR — command not found: {cmd[0]}]\n"
            print(err)
            lines.append(err)

        output = "".join(lines)
        self._save(raw_path, cmd_str, output)
        return output

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _save(path: Path, cmd_str: str, output: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        header = f"# Command : {cmd_str}\n# Timestamp: {ts}\n# {'=' * 60}\n\n"
        path.write_text(header + output)
