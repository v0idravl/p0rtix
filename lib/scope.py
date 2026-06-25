import socket


class Scope:
    """
    Enforces target scope so follow-up scans never touch out-of-scope hosts.

    In-scope:
      - The target IP itself
      - The explicitly provided domain (e.g. test.htb)
      - Any subdomain of that domain (*.test.htb)
      - Any hostname that resolves to the target IP
      - A vhost adopted from the in-scope IP's own redirect (see adopt())
    """

    def __init__(self, ip: str, domain: str | None = None):
        self.ip = ip
        self.domain = domain.lower().rstrip(".") if domain else None

    def adopt(self, hostname: str) -> None:
        """Bring a hostname discovered FROM the in-scope IP (e.g. the IP's own HTTP
        redirect target) into scope. With no domain set yet, adopt an FQDN as the
        scope domain so its vhosts/subdomains are in scope too. Tight by design:
        pass only the in-scope IP's own redirect/vhost target here, never an
        arbitrary external host."""
        host = (hostname or "").lower().rstrip(".")
        if not host or host == self.ip:
            return
        # Only adopt a real hostname (has a dot, not a bare IPv4 literal).
        if "." in host and not all(p.isdigit() for p in host.split(".")):
            if self.domain is None:
                self.domain = host

    def check(self, hostname: str) -> bool:
        hostname = hostname.lower().rstrip(".")

        if hostname == self.ip:
            return True

        if self.domain:
            if hostname == self.domain or hostname.endswith("." + self.domain):
                return True

        # Fall back to DNS — accept if it resolves to the target IP
        try:
            resolved = socket.gethostbyname(hostname)
            return resolved == self.ip
        except OSError:
            return False

    def filter_urls(self, urls: list[str]) -> tuple[list[str], list[str]]:
        """Split a URL list into (in_scope, out_of_scope)."""
        from urllib.parse import urlparse
        in_scope, out_of_scope = [], []
        for url in urls:
            try:
                host = urlparse(url).hostname or ""
                (in_scope if self.check(host) else out_of_scope).append(url)
            except Exception:
                out_of_scope.append(url)
        return in_scope, out_of_scope
