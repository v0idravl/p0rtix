import shlex
import subprocess
from datetime import datetime
from pathlib import Path

from lib.workspace import Workspace


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

    @property
    def ws(self) -> Workspace:
        return self._ws

    # ── Public API ────────────────────────────────────────────────────────────

    def run(self, cmd: list[str], label: str, timeout: int = 300) -> str:
        """
        Run a command, capture output, save to raw/, return stdout as string.
        Failures are recorded in the raw file but do not raise exceptions.
        """
        raw_path = self._ws.raw_dir / f"{self._ws.next_raw_label(label)}.txt"
        cmd_str = shlex.join(cmd)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            output = result.stdout
            if result.returncode != 0 and result.stderr.strip():
                output += f"\n[stderr]\n{result.stderr}"
        except subprocess.TimeoutExpired:
            output = f"[TIMEOUT — command ran for {timeout}s without completing]\n"
        except FileNotFoundError:
            output = f"[ERROR — command not found: {cmd[0]}]\n"

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
