import sys

import pytest

from lib import deps
import p0rtix


def test_check_deps_no_install_skips_prompts_and_returns_available(monkeypatch):
    monkeypatch.setattr(
        deps,
        "TOOLS",
        {
            "nmap": {"required": True, "apt": "nmap"},
            "whatweb": {"required": False, "apt": "whatweb"},
        },
    )
    monkeypatch.setattr(deps, "_is_available", lambda tool, meta: tool == "nmap")

    def fail_input(prompt):
        raise AssertionError("check_deps(no_install=True) should not prompt")

    def fail_install(tool, meta):
        raise AssertionError("check_deps(no_install=True) should not install")

    monkeypatch.setattr("builtins.input", fail_input)
    monkeypatch.setattr(deps, "_install", fail_install)

    assert deps.check_deps(install_missing=False) == {"nmap"}


def test_parse_args_supports_no_install(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["p0rtix.py", "10.0.0.5", "--no-install"])

    args = p0rtix.parse_args()

    assert args.no_install is True
