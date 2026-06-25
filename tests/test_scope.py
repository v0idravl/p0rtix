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


def test_adopt_brings_ip_own_redirect_vhost_into_scope(monkeypatch):
    # Simulate the Analytics case: domain unknown at scan time, the in-scope IP's
    # root 302-redirects to a vhost name that does NOT resolve via DNS.
    monkeypatch.setattr(socket, "gethostbyname",
                        lambda hostname: (_ for _ in ()).throw(socket.gaierror))
    scope = Scope("10.129.229.224")  # no domain

    assert not scope.check("analytical.htb")  # rejected before adopt
    scope.adopt("analytical.htb")
    assert scope.check("analytical.htb")          # apex now in scope
    assert scope.check("data.analytical.htb")     # and its subdomains/vhosts


def test_adopt_ignores_ip_literals_and_bare_labels(monkeypatch):
    monkeypatch.setattr(socket, "gethostbyname",
                        lambda hostname: (_ for _ in ()).throw(socket.gaierror))
    scope = Scope("10.0.0.5")

    scope.adopt("10.0.0.9")   # IPv4 literal — not a domain
    scope.adopt("localhost")  # bare label — not an FQDN
    assert scope.domain is None
    assert not scope.check("10.0.0.9")
    assert not scope.check("localhost")


def test_adopt_does_not_override_an_existing_domain():
    scope = Scope("10.0.0.5", "example.internal")
    scope.adopt("attacker.evil")
    assert scope.domain == "example.internal"
    assert not scope.check("attacker.evil")


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
