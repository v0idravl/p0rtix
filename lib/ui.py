"""
Terminal output helpers — colored status symbols with a debug verbosity gate.

The screen output is a live signal of what the scan is doing and what it found;
the full detail always lands in findings.md / raw/. Default mode is concise:
phase headers, finds, and warnings. `--debug` (set_debug(True)) adds the per-tool
step chatter useful for troubleshooting.

No third-party deps — plain ANSI, auto-disabled when stdout is not a TTY or
NO_COLOR is set, so piped/redirected output stays clean.
"""
import os
import sys

_DEBUG = False
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

# ANSI
_RESET = "\033[0m"
_BOLD  = "\033[1m"
_DIM   = "\033[2m"
_C = {
    "blue":   "\033[34m",
    "green":  "\033[32m",
    "yellow": "\033[33m",
    "red":    "\033[31m",
    "grey":   "\033[90m",
    "cyan":   "\033[36m",
}


def set_debug(enabled: bool) -> None:
    global _DEBUG
    _DEBUG = enabled


def debug_enabled() -> bool:
    return _DEBUG


def _c(text: str, color: str, bold: bool = False) -> str:
    if not _COLOR:
        return text
    pre = _C.get(color, "")
    if bold:
        pre = _BOLD + pre
    return f"{pre}{text}{_RESET}"


def _emit(symbol: str, color: str, msg: str, bold: bool = False) -> None:
    print(f"{_c(symbol, color, bold)} {msg}")


# ── Always shown ──────────────────────────────────────────────────────────────

def info(msg: str) -> None:
    """Status / what we're doing."""
    _emit("[*]", "blue", msg)


def good(msg: str) -> None:
    """A find worth surfacing."""
    _emit("[+]", "green", _c(msg, "green", bold=True) if _COLOR else msg)


def warn(msg: str) -> None:
    _emit("[!]", "yellow", msg)


def lose(msg: str) -> None:
    """A negative result worth showing in default mode (e.g. denied access)."""
    _emit("[-]", "grey", msg)


def phase(title: str) -> None:
    """Phase / section header — bold, spaced for scannability."""
    print()
    print(_c(f"══ {title} ", "cyan", bold=True) + _c("═" * max(0, 50 - len(title)), "cyan"))


def found(label: str, value: str) -> None:
    """High-signal discovery: `label: value` with the value highlighted."""
    _emit("[+]", "green", f"{label}: {_c(value, 'green', bold=True) if _COLOR else value}")


# ── Debug-only ────────────────────────────────────────────────────────────────

def debug(msg: str) -> None:
    """Per-tool step detail — only with --debug."""
    if _DEBUG:
        print(f"{_c('[d]', 'grey')} {_c(msg, 'grey')}")


def step(msg: str) -> None:
    """A routine sub-step (e.g. 'running ldapdomaindump'). Debug-only."""
    if _DEBUG:
        _emit("[*]", "grey", msg)
