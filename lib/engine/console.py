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
import sys

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


def run_console(scheduler, registry, facts, posture, *, banner=None,
                headless=False) -> None:
    """Entry point. Applies the dial autorun, then launches the dashboard
    (Textual) or the line-mode fallback.

    Line-mode is chosen when Textual is absent, when ``headless`` is set, or when
    stdin is not a TTY — the last case lets a piped command script drive the
    engine non-interactively (`printf 'run-all\\nexit\\n' | … --mode console`)."""
    router = CommandRouter(scheduler, registry, facts, posture)
    apply_dial_autorun(scheduler, posture)

    line_mode = headless or not _HAS_TEXTUAL or not sys.stdin.isatty()
    if not line_mode:
        _run_textual(router, scheduler, registry, facts, posture)
        return

    if not _HAS_TEXTUAL:
        print("[*] textual not installed — using line mode "
              "(`pip install textual` for the dashboard). Type 'help'.")
    if banner:
        print(banner)
    LineConsole(router).run()


# ── Textual dashboard (only touched when textual is importable) ───────────────
# Tier → (glyph, rich-colour) for the action list and detail pane.
_TIER_STYLE = {
    Tier.PASSIVE: ("·", "dim"),
    Tier.GREEN:   ("●", "green"),
    Tier.YELLOW:  ("●", "yellow"),
    Tier.RED:     ("●", "red"),
}


def _tier_tag(tier: Tier) -> str:
    glyph, colour = _TIER_STYLE[tier]
    return f"[{colour}]{glyph}[/] [{colour}]{tier.label}[/]"


def _state_markup(facts, posture, scheduler) -> str:
    """Left-pane campaign state — a compact mirror of the `status` command:
    target, domain, posture, how many ports are known, one-line loot, lockout,
    actions run, and any per-protocol status."""
    s = facts.snapshot()
    st = scheduler.status()
    red = "on" if posture.red_unlocked() else "off"
    n_tcp = sum(1 for proto, _ in s["open_ports"] if proto == "tcp")
    n_udp = sum(1 for proto, _ in s["open_ports"] if proto == "udp")
    ports = f"[b]{len(s['open_ports'])}[/] known"
    if s["open_ports"]:
        ports += f"  [dim]({n_tcp} tcp" + (f" · {n_udp} udp" if n_udp else "") + ")[/]"
    lockout = s["lockout"] if s["lockout"] != -1 else "?"
    rows = [
        f"[b]TARGET[/]   {s['ip']}",
        f"[b]DOMAIN[/]   {s['domain'] or '—'}",
        f"[b]POSTURE[/]  {_tier_tag(posture.level)}  [dim](dial {posture.dial} · red {red})[/]",
        "",
        f"[b]PORTS[/]    {ports}",
        f"[b]LOOT[/]     {len(s['users'])} users · "
        f"[b]{len(s['valid_creds'])}[/]/{len(s['creds'])} creds [dim](valid/cand)[/]",
        f"[b]HASHES[/]   {', '.join(s['hashes']) or '—'}",
        f"[b]LOCKOUT[/]  {lockout}",
        f"[b]ACTIONS[/]  {st['completed']} run",
    ]
    if s["proto_status"]:
        rows += ["", "[b]STATUS[/]"] + [
            f"  {k} = {v}" for k, v in sorted(s["proto_status"].items())
        ]
    return "\n".join(rows)


def _run_textual(router, scheduler, registry, facts, posture) -> None:
    """Launch the full-screen operator dashboard (blocks until the user quits)."""
    _build_dashboard(router, scheduler, registry, facts, posture).run()


def _build_dashboard(router, scheduler, registry, facts, posture):
    """Build the operator dashboard App (without running it — the test harness
    drives it via Textual's Pilot). Imports Textual lazily so this module imports
    cleanly without the dependency.

    Layout (top→bottom): header · [state | actions] · action detail · result log ·
    command input · footer. Actions are a navigable/clickable list grouped
    Available / Dormant / Exhausted; selecting a runnable one dispatches it on a
    worker thread (so a multi-minute scan never freezes the UI) and streams the
    result into the log via the scheduler's on_output hook."""
    from rich.markdown import Markdown
    from textual.app import App, ComposeResult
    from textual.containers import Horizontal
    from textual.widgets import (Footer, Header, Input, Label, ListItem,
                                 ListView, RichLog, Static)

    class _ActionItem(ListItem):
        """A ListView row that remembers which action it represents."""
        def __init__(self, label: str, *, action_name=None, runnable=False,
                     header=False):
            super().__init__(Label(label))
            self.label_text = label            # plain text, for tests/inspection
            self.action_name = action_name
            self.runnable = runnable
            if header:
                self.add_class("group")
                self.disabled = True

    class Dashboard(App):
        TITLE = "p0rtix — operator console"
        CSS = """
        #top { height: 45%; }
        #state {
            width: 34%; border: round $primary; padding: 0 1;
        }
        #actions-title { dock: top; padding: 0 1;
            background: $primary; color: $text; text-style: bold; }
        #actionpane { width: 1fr; border: round $accent; }
        #actions { height: 1fr; background: $surface; }
        #actions > .group { color: $text-muted; text-style: bold; }
        #detail { height: 5; border: round $secondary; padding: 0 1; }
        #log { height: 1fr; border: round $primary; }
        /* No dock: let the input flow as the last child so it sits directly
           above the Footer instead of overlapping it. */
        #cmd { height: 3; }
        """
        BINDINGS = [
            ("ctrl+c", "quit", "Quit"),
            ("ctrl+r", "run_all", "Run all (≤posture)"),
            ("ctrl+o", "focus_cmd", "Command"),
            ("f1", "help", "Help"),
        ]

        def compose(self) -> ComposeResult:
            yield Header(show_clock=True)
            with Horizontal(id="top"):
                yield Static(_state_markup(facts, posture, scheduler), id="state")
                with Horizontal(id="actionpane"):
                    yield Static("ACTIONS  (↑↓ to browse · enter/click to run)",
                                 id="actions-title")
                    yield ListView(id="actions")
            yield Static("Select an action to see what it does and the trace it "
                         "leaves.", id="detail")
            yield RichLog(id="log", highlight=True, markup=True, wrap=True)
            yield Input(placeholder="command — type 'help', or run actions from the "
                        "list above", id="cmd")
            yield Footer()

        # ── lifecycle ──────────────────────────────────────────────────────────
        def on_mount(self) -> None:
            scheduler._on_output = self._on_action_output
            facts.subscribe(self._on_fact)
            self._log("[b green]p0rtix operator console[/] — F1 for help. "
                      "Actions unlock as facts arrive; greyed-out rows show what "
                      "they're waiting on.")
            self._rebuild_actions()

        # ── fact events (may arrive on a worker thread OR the UI thread) ─────────
        def _marshal(self, fn, *args) -> None:
            """Run `fn` on the UI thread. Actions run on worker threads (→ marshal),
            but command-box mutations (`set domain`, `add user`) emit facts on the
            UI thread already, where call_from_thread would raise — so fall back to
            a direct call."""
            try:
                self.call_from_thread(fn, *args)
            except RuntimeError:
                fn(*args)

        def _on_fact(self, _ev) -> None:
            self._marshal(self._refresh)

        def _on_action_output(self, name, summary, rendered) -> None:
            self._marshal(self._emit_result, name, summary, rendered)

        # ── rendering ───────────────────────────────────────────────────────────
        def _refresh(self) -> None:
            self.query_one("#state", Static).update(
                _state_markup(facts, posture, scheduler))
            self._rebuild_actions()

        def _action_row(self, action, state, info):
            """(label_markup, runnable) for one action row, by planner state.
            Per-instance fan-out (e.g. version_detect/port) collapses to ×N."""
            glyph, colour = _TIER_STYLE[action.tier]
            name = action.name
            if state == "available":
                tag = f" [dim]×{info}[/]" if info and info > 1 else ""
                desc = action.footprint.summary or ""
                return f"[{colour}]{glyph}[/] {name}{tag}  [dim]{desc}[/]", True
            if state == "exhausted":
                return f"[dim]✓ {name}[/]", False
            if state == "dormant":
                reason = ", ".join(r.label for r in info) or "preconditions"
                return f"[dim]○ {name} — needs {reason}[/]", False
            # blocked: gate met, posture/tool holds it back
            return f"[yellow]◐[/] [dim]{name} — {info}[/]", False

        def _rebuild_actions(self) -> None:
            lv = self.query_one("#actions", ListView)
            keep = None
            cur = lv.highlighted_child
            if isinstance(cur, _ActionItem):
                keep = cur.action_name
            lv.clear()

            # Grouped by path: each service/branch is a section that lights up and
            # progresses as facts arrive (step into the LDAP path, the SMB path…).
            for group, rows in registry.grouped(facts, posture, scheduler.tried):
                ps = facts.proto_status(group)
                badge = f"  [dim]\\[{ps.value}][/]" if ps is not None else ""
                lv.append(_ActionItem(f"▸ {group.upper()}{badge}", header=True))
                for action, state, info in rows:
                    label, runnable = self._action_row(action, state, info)
                    lv.append(_ActionItem(label, action_name=action.name,
                                          runnable=runnable))

            if keep:                       # restore highlight after rebuild
                for i, child in enumerate(lv.children):
                    if isinstance(child, _ActionItem) and child.action_name == keep:
                        lv.index = i
                        break

        def _emit_result(self, name, summary, rendered) -> None:
            log = self.query_one("#log", RichLog)
            log.write(f"[b cyan]✓ {name}[/] — {summary or 'done'}")
            if rendered.strip():
                log.write(Markdown(rendered))

        def _log(self, text) -> None:
            self.query_one("#log", RichLog).write(text)

        # ── interaction ─────────────────────────────────────────────────────────
        def on_list_view_highlighted(self, event) -> None:
            item = event.item
            detail = self.query_one("#detail", Static)
            if not isinstance(item, _ActionItem) or not item.action_name:
                detail.update("Select an action to see what it does and the trace "
                              "it leaves.")
                return
            a = registry.get(item.action_name)
            if a is None:
                return
            why = registry.why(item.action_name, facts, posture, scheduler.tried)
            fp = a.footprint
            lines = [f"{_tier_tag(a.tier)}  [b]{a.name}[/]   [i]{why}[/]"]
            if fp.summary:
                lines.append(fp.summary)
            trace = []
            if fp.network:
                trace.append(f"network: {fp.network}")
            if fp.windows_events:
                trace.append("win-events: " + ", ".join(fp.windows_events))
            if fp.linux_logs:
                trace.append("linux: " + ", ".join(fp.linux_logs))
            if trace:
                lines.append("[dim]" + "   ".join(trace) + "[/]")
            detail.update("\n".join(lines))

        def on_list_view_selected(self, event) -> None:
            item = event.item
            if not isinstance(item, _ActionItem) or not item.action_name:
                return
            if item.runnable:
                self._run_action(item.action_name)
            else:
                self._log(f"[yellow]{item.action_name}[/]: "
                          + registry.why(item.action_name, facts, posture,
                                         scheduler.tried))

        def _run_action(self, name) -> None:
            self._log(f"[b]› running [cyan]{name}[/]…[/]")
            self.run_worker(lambda: self._dispatch(name), thread=True,
                            group="actions", exit_on_error=False)

        def _dispatch(self, name) -> None:          # worker thread
            n = scheduler.run_action(name)
            if not n:
                why = registry.why(name, facts, posture, scheduler.tried)
                self.call_from_thread(self._log, f"[yellow]{name}: {why}[/]")
            self.call_from_thread(self._refresh)

        def on_input_submitted(self, event: Input.Submitted) -> None:
            line = event.value.strip()
            event.input.value = ""
            if not line:
                return
            if line.lower() in ("exit", "quit"):
                self.exit()
                return
            self._log(f"[b]> {line}[/]")
            # run/run-all/auto go through the worker so the UI stays responsive;
            # everything else is cheap and runs inline.
            low = line.lower()
            if low in ("run-all", "auto"):
                self.action_run_all()
            elif low.startswith("run "):
                self._run_action(line.split(None, 1)[1].strip())
            else:
                out = router.dispatch(line)
                if out:
                    self._log(out)
                self._refresh()

        # ── bindings ─────────────────────────────────────────────────────────────
        def action_run_all(self) -> None:
            self._log(f"[b]› run-all at/below [cyan]{posture.level.label}[/]…[/]")
            self.run_worker(lambda: scheduler.run_all_at_or_below(posture),
                            thread=True, group="actions", exit_on_error=False)

        def action_focus_cmd(self) -> None:
            self.query_one("#cmd", Input).focus()

        def action_help(self) -> None:
            self._log(router.dispatch("help"))

    return Dashboard()
