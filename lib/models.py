from dataclasses import dataclass, field


@dataclass
class Service:
    port: int
    proto: str      # "tcp" | "udp"
    name: str       # service name from nmap (e.g. "ssh", "http", "microsoft-ds")
    version: str    # version banner (e.g. "OpenSSH 8.9p1")
    is_web: bool
    scheme: str     # "http" | "https" | "" for non-web
    hostname: str = ""  # populated for vhost follow-up jobs


@dataclass
class Discovery:
    type: str       # "vhost" | "ssl_san" | "redirect"
    hostname: str   # the newly discovered hostname
    port: int
    scheme: str     # "http" | "https"
    source: str     # human-readable origin (e.g. "ffuf vhost bust port 80")
