"""
p0rtix engine — stateful planner over a shared fact store.

This package replaces the linear fan-out scan pipeline with an operator-driven
model: every capability is a reified `Action` (risk tier + OPSEC footprint +
fact gates + handler), the `FactStore` emits events as facts are learned, the
`Scheduler` re-evaluates which actions are available on each new fact, and the
operator deliberately raises a session-wide noise posture rather than the tool
firing everything at once.

Built as a strangler inside p0rtix: existing handler bodies in lib/services.py,
lib/web.py, lib/credsmode.py are wrapped as Action handlers — only the
orchestration is replaced.
"""
