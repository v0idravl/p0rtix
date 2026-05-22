import threading
from datetime import date
from pathlib import Path

_W     = 80
_THIN  = "─" * _W   # service-block separator
_THICK = "═" * _W   # major-section separator

_VERBOSE = False


def set_verbose(v: bool) -> None:
    global _VERBOSE
    _VERBOSE = v

_BANNER = (
    r"         )         )           " + "\n"
    r"      ( /( (    ( /( (      )  " + "\n"
    r" `  )    )\()))(   )\()))\  ( /(  " + "\n"
    r" /(/(   ((_)\(()\ (_))/((_) )\()) " + "\n"
    r"((_)_\  /  (_)((_)| |_  (_)((_)\  " + "\n"
    r"| '_ \)| () || '_||  _| | |\ \ /  " + "\n"
    r"| .__/  \__/ |_|   \__| |_|/_\_\  " + "\n"
    r"|_|                               "
)


class FindingsSink:
    """
    Shared write API for Findings and ServiceBuffer.
    Subclasses implement _write(text).
    """

    def _write(self, text: str):
        raise NotImplementedError

    def add_summary(self, item: str):
        """Record a high-signal finding for the executive summary. No-op in base."""
        pass

    def absorb(self, buf: "ServiceBuffer"):
        """Merge a completed ServiceBuffer's content and summary into this sink."""
        content = buf.render()
        if content:
            self._write(content)
        for item in buf.drain_summary():
            self.add_summary(item)

    def h3(self, title: str):    self._write(f"\n### {title}\n")
    def h4(self, title: str):    self._write(f"\n#### {title}\n")
    def cmd(self, command: str): self._write(f"\n> `{command}`\n")
    def bullet(self, text: str): self._write(f"- {text}\n")
    def note(self, text: str):
        notes = getattr(self, '_notes_log', None)
        if notes is not None:
            notes.append(text)
        if _VERBOSE:
            self._write(f"\n> **Note:** {text}\n")
    def blank(self):             self._write("\n")

    def code_block(self, content: str, lang: str = ""):
        if content.strip():
            self._write(f"\n```{lang}\n{content.rstrip()}\n```\n")

    def raw_section(self, title: str, command: str, content: str):
        self.h4(title)
        self.cmd(command)
        if content.strip():
            self.code_block(content)

    def table(self, headers: list[str], rows: list[list[str]]):
        if not rows:
            return
        col_widths = [
            max(len(h), max((len(r[i]) for r in rows), default=0))
            for i, h in enumerate(headers)
        ]
        sep        = "| " + " | ".join("-" * w for w in col_widths) + " |"
        header_row = "| " + " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers)) + " |"
        lines = ["\n", header_row, sep]
        for row in rows:
            lines.append(
                "| " + " | ".join(str(row[i]).ljust(col_widths[i]) for i in range(len(headers))) + " |"
            )
        self._write("\n".join(lines) + "\n")


class Findings(FindingsSink):
    """
    Thread-safe, live-updating writer for findings.md.

    Global sections (port table, discovery, searchsploit) write directly.
    Service sections accumulate in ServiceBuffers passed to parallel handlers
    and are flushed in port order via flush_service_buffer() after the
    parallel phase completes.
    """

    def __init__(self, path: Path, ip: str, domain: str | None):
        self._path = path
        self._lock = threading.Lock()
        self._summary: list[str] = []
        self._notes_log: list[str] = []
        self._write_header(ip, domain)

    # ── Public API ────────────────────────────────────────────────────────────

    def h2(self, title: str):
        self._write(f"\n{_THICK}\n## {title}\n{_THICK}\n")

    def add_summary(self, item: str):
        with self._lock:
            self._summary.append(item)

    def flush_service_buffer(self, buf: "ServiceBuffer"):
        """Append a completed service buffer to findings (call in port order)."""
        for item in buf.drain_summary():
            self.add_summary(item)
        self._notes_log.extend(buf.drain_notes())
        content = buf.render()
        if content.strip():
            self._write(f"\n{_THIN}\n{content}")

    def finalize(self):
        if self._summary:
            self._write(f"\n{_THICK}\n## Key Findings\n{_THICK}\n")
            for item in self._summary:
                self._write(f"- {item}\n")
        if self._notes_log and not _VERBOSE:
            self._write(f"\n{_THICK}\n## Notices\n{_THICK}\n")
            for note in sorted(set(self._notes_log)):
                self._write(f"- {note}\n")
        footer = (
            f"\n{_THICK}\n"
            f"  p0rtix — scan complete                    by v0idravl\n"
            f"{_THICK}\n"
        )
        self._write(f"\n---\n\n```\n{footer}```\n")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _write_header(self, ip: str, domain: str | None):
        meta_lines = [f"  {'Target':<10} {ip}"]
        if domain:
            meta_lines.append(f"  {'Domain':<10} {domain}")
        meta_lines.append(f"  {'Date':<10} {date.today()}")
        meta_block = "\n".join(meta_lines)

        header = (
            f"```\n{_BANNER}\n```\n\n"
            f"# p0rtix — {ip}\n\n"
            f"```\n{meta_block}\n```\n\n"
            f"{_THICK}\n"
        )
        self._path.write_text(header)

    def _write(self, text: str):
        with self._lock:
            with self._path.open("a") as fh:
                fh.write(text)


class ServiceBuffer(FindingsSink):
    """
    In-memory accumulator with the same write API as Findings.
    One instance per service in the parallel executor; flushed to the
    main Findings in port order after all threads complete.
    """

    def __init__(self, port: int, proto: str):
        self.port    = port
        self.proto   = proto
        self._chunks: list[str] = []
        self._summary: list[str] = []
        self._notes_log: list[str] = []

    def _write(self, text: str):
        self._chunks.append(text)

    def add_summary(self, item: str):
        self._summary.append(item)

    def drain_summary(self) -> list[str]:
        items, self._summary = self._summary, []
        return items

    def drain_notes(self) -> list[str]:
        prefixed = [f"{self.proto.upper()} {self.port}: {n}" for n in self._notes_log]
        self._notes_log = []
        return prefixed

    def render(self) -> str:
        return "".join(self._chunks)
