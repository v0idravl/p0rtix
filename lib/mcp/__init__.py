"""p0rtix MCP server — a generic, introspective interface over the recon engine.

`session.py` holds the engine-facing logic (no MCP SDK dependency, fully
testable). `server.py` wraps it as a FastMCP stdio server. The core engine never
imports either module, so the stdlib-only runtime is untouched unless `--mode
mcp` is used.
"""
