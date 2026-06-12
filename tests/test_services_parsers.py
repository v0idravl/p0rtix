"""Parser tests for lib/services.py helpers that feed the fact store.

These guard the brittle text-scraping seams against tool-output format drift —
the exact failure the Forest live run surfaced, where a netexec `--users` format
change silently dropped the authoritative user list (incl. svc-alfresco)."""
from lib import services
from lib.engine.facts import FactStore


class _Buf:
    """Minimal Findings stand-in — only what the parsers call."""
    def __init__(self):
        self.bullets, self.summaries, self.blocks = [], [], []

    def bullet(self, s): self.bullets.append(s)
    def add_summary(self, s): self.summaries.append(s)
    def code_block(self, s): self.blocks.append(s)


class _Runner:
    def __init__(self, ws): self.ws = ws


# Current netexec --users table output (as seen live against Forest).
_NXC_TABLE = """\
SMB  10.0.0.1  445  FOREST  [*] Windows Server 2016 (name:FOREST) (domain:htb.local)
SMB  10.0.0.1  445  FOREST  [+] htb.local\\:
SMB  10.0.0.1  445  FOREST  -Username-      -Last PW Set-       -BadPW- -Description-
SMB  10.0.0.1  445  FOREST  Administrator   2021-08-31 00:51:58 0       Built-in account
SMB  10.0.0.1  445  FOREST  Guest           <never>             0       Built-in guest
SMB  10.0.0.1  445  FOREST  krbtgt          2019-09-18 10:53:23 0       KDC Service Account
SMB  10.0.0.1  445  FOREST  $331000-VK4AD   <never>             0
SMB  10.0.0.1  445  FOREST  svc-alfresco    2026-06-11 23:43:51 0
SMB  10.0.0.1  445  FOREST  FAKE$           <never>             0
SMB  10.0.0.1  445  FOREST  [*] Enumerated 6 local users: HTB
"""

# Legacy netexec format still in the wild.
_NXC_LEGACY = """\
SMB  10.0.0.1  445  DC  Administrator badpwdcount: 0 baddpwdtime: ...
SMB  10.0.0.1  445  DC  svc-alfresco badpwdcount: 0 baddpwdtime: ...
"""


def _run(output, tmp_path):
    fs = FactStore("10.0.0.1", None, "parse-test", str(tmp_path))
    services._parse_nxc_users(output, _Buf(), _Runner(fs))
    return fs


def test_parse_nxc_users_new_table_format(tmp_path):
    fs = _run(_NXC_TABLE, tmp_path)
    users = set(fs.snapshot()["users"])
    # The accounts anonymous LDAP hides must be recovered here.
    assert {"Administrator", "krbtgt", "svc-alfresco", "$331000-VK4AD"} <= users
    assert "FAKE$" not in users          # machine accounts dropped


def test_parse_nxc_users_legacy_format(tmp_path):
    fs = _run(_NXC_LEGACY, tmp_path)
    assert {"Administrator", "svc-alfresco"} <= set(fs.snapshot()["users"])


def test_parse_nxc_users_marks_complete(tmp_path):
    fs = _run(_NXC_TABLE, tmp_path)
    assert fs.users_complete
