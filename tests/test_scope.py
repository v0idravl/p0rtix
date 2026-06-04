import socket

from lib.scope import Scope


def test_scope_accepts_target_domain_subdomains_and_matching_dns(monkeypatch):
    def fake_gethostbyname(hostname):
        if hostname == "alias.internal":
            return "10.0.0.5"
        raise socket.gaierror

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)

    scope = Scope("10.0.0.5", "example.internal")

    assert scope.check("10.0.0.5")
    assert scope.check("example.internal")
    assert scope.check("portal.example.internal")
    assert scope.check("portal.example.internal.")
    assert scope.check("alias.internal")


def test_scope_rejects_external_and_unresolved_hosts(monkeypatch):
    def fake_gethostbyname(hostname):
        if hostname == "external.example":
            return "203.0.113.20"
        raise socket.gaierror

    monkeypatch.setattr(socket, "gethostbyname", fake_gethostbyname)

    scope = Scope("10.0.0.5", "example.internal")

    assert not scope.check("badexample.internal")
    assert not scope.check("external.example")
    assert not scope.check("does-not-resolve.invalid")


def test_filter_urls_splits_in_scope_and_out_of_scope_without_following_links(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname", lambda hostname: "203.0.113.20")
    scope = Scope("10.0.0.5", "example.internal")

    in_scope, out_of_scope = scope.filter_urls([
        "https://portal.example.internal/path",
        "https://example.com/vendor-docs",
        "not a url",
    ])

    assert in_scope == ["https://portal.example.internal/path"]
    assert out_of_scope == ["https://example.com/vendor-docs", "not a url"]
