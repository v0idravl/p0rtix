"""
The operator console.

Two front-ends over the same `CommandRouter.dispatch(line)`:

  * the full-screen **Textual** dashboard (panes for state / actions / log), used
    when `textual` is installed;
  * a minimal **line-mode** driver used as a graceful fallback when it is not,
    so the engine always runs.

No engine logic lives here — both front-ends only parse input and render output.
The dashboard's reactive pane updates are driven by `FactStore` events bridged
onto the UI thread; that wiring lives in the Textual section and is exercised on
a box where `textual` is installed (the line-mode path is what the unit tests
drive).
"""
from __future__ import annotations

import importlib.util

from lib.engine.action import Tier
from lib.engine.commands import CommandRouter

_HAS_TEXTUAL = importlib.util.find_spec("textual") is not None


def apply_dial_autorun(scheduler, posture) -> int:
    """Honour the `--level` dial at launch: auto-climb the ladder up to the dial's
    ceiling, running everything available at each step. Returns total dispatched.
    Dial 0 leaves the session fully manual at PASSIVE."""
    ceiling = posture.auto_ceiling()
    if ceiling is None:
        return 0
    total = 0
    for tier in (Tier.GREEN, Tier.YELLOW, Tier.RED):
        if tier > ceiling:
            break
        if not posture.raise_to(tier):   # RED needs the dial/arming to permit it
            break
        total += scheduler.run_all_at_or_below(posture)
    return total


class LineConsole:
    """A dependency-free REPL over the command router. Used when Textual is
    absent and as the unit-test seam."""

    PROMPT = "p0rtix> "

    def __init__(self, router: CommandRouter):
        self._router = router

    def run(self, reader=None, writer=None) -> None:
        # Resolve at call time so a test's builtins.input/print monkeypatch applies.
        reader = reader or input
        writer = writer or print
        while True:
            try:
                line = reader(self.PROMPT)
            except (EOFError, KeyboardInterrupt):
                break
            if line is None:
                break
            if line.strip().lower() in ("exit", "quit"):
                break
            out = self._router.dispatch(line)
            if out:
                writer(out)


def run_console(scheduler, registry, facts, posture, *, banner=None) -> None:
    """Entry point. Applies the dial autorun, then launches the dashboard
    (Textual) or the line-mode fallback."""
    router = CommandRouter(scheduler, registry, facts, posture)
    apply_dial_autorun(scheduler, posture)

    if _HAS_TEXTUAL:
        _run_textual(router, scheduler, registry, facts, posture)
    else:
        print("[*] textual not installed — using line mode "
              "(`pip install textual` for the dashboard). Type 'help'.")
        if banner:
            print(banner)
        LineConsole(router).run()


# ── Textual dashboard (only touched when textual is importable) ───────────────
def _run_textual(router, scheduler, registry, facts, posture) -> None:
    """Build and run the full-screen dashboard. Imports Textual lazily so this
    module imports cleanly without the dependency."""
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Footer, Header, Input, RichLog, Static

    GLYPH = {Tier.PASSIVE: "·", Tier.GREEN: "[green]●[/]",
             Tier.YELLOW: "[yellow]●[/]", Tier.RED: "[red]●[/]"}

    class Dashboard(App):
        CSS = """
        #state { width: 38%; border: round $primary; }
        #actions { width: 62%; border: round $primary; }
        #log { height: 1fr; border: round $primary; }
        Input { dock: bottom; }
        """
        BINDINGS = [("ctrl+c", "quit", "Quit")]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal():
                yield Static(id="state")
                yield Static(id="actions")
            yield RichLog(id="log", highlight=True, markup=True)
            yield Input(placeholder="command (try 'help')")
            yield Footer()

        def on_mount(self) -> None:
            facts.subscribe(self._on_fact)
            self._refresh()

        def _on_fact(self, _ev) -> None:
            # Marshalled onto the UI thread — handlers may run on worker threads.
            self.call_from_thread(self._refresh)

        def _refresh(self) -> None:
            self.query_one("#state", Static).update(router.dispatch("status"))
            self.query_one("#actions", Static).update(router.dispatch("actions --all"))

        def on_input_submitted(self, event: Input.Submitted) -> None:
            line = event.value.strip()
            event.input.value = ""
            if line.lower() in ("exit", "quit"):
                self.exit()
                return
            self.query_one("#log", RichLog).write(f"[b]> {line}[/]")
            out = router.dispatch(line)
            if out:
                self.query_one("#log", RichLog).write(out)
            self._refresh()

    Dashboard().run()
