import os
import shutil
import subprocess
import sys
from pathlib import Path

# Tool name → install instructions.
# "apt"  — installed with: apt install -y <pkg>
# "go"   — installed with: go install <pkg>
# "pip"  — installed with: pip3 install <pkg>
# required=True → abort if missing; False → skip gracefully
TOOLS: dict[str, dict] = {
    # Core — scan cannot run without these
    "nmap":                  {"apt": "nmap",                            "required": True},
    "curl":                  {"apt": "curl",                            "required": True},
    "ffuf":                  {"apt": "ffuf",                            "required": True},

    # Web
    "whatweb":               {"apt": "whatweb",                         "required": False},
    "gospider":              {"go":  "github.com/jaeles-project/gospider@latest", "required": False},
    "testssl.sh":            {"apt": "testssl.sh",                      "required": False},
    "wpscan":                {"apt": "wpscan",                          "required": False},

    # SMB
    "nxc":                   {"apt": "netexec",                         "required": False},
    "smbclient":             {"apt": "smbclient",                       "required": False},
    "smbmap":                {"apt": "smbmap",                          "required": False},

    # SNMP
    "onesixtyone":           {"apt": "onesixtyone",                     "required": False},
    "snmpwalk":              {"apt": "snmp",                            "required": False},
    "snmp-check":            {"apt": "snmpcheck",                       "required": False},

    # LDAP / Active Directory
    "ldapsearch":            {"apt": "ldap-utils",                      "required": False},
    "ldapdomaindump":        {"pip": "ldapdomaindump",                  "required": False},
    "bloodhound-python":     {"pip": "bloodhound",                      "required": False},
    "certipy":               {"pip": "certipy-ad",                      "required": False},

    # Kerberos
    "kerbrute":              {"go":  "github.com/ropnop/kerbrute@latest", "required": False},
    "impacket-GetNPUsers":   {"apt": "python3-impacket",                "required": False},
    "impacket-GetUserSPNs":  {"apt": "python3-impacket",                "required": False},
    "impacket-lookupsid":    {"apt": "python3-impacket",                "required": False},

    # DNS
    "dig":                   {"apt": "dnsutils",                        "required": False},
    "dnsrecon":              {"apt": "dnsrecon",                        "required": False},

    # Databases
    "mysql":                 {"apt": "default-mysql-client",            "required": False},
    "psql":                  {"apt": "postgresql-client",               "required": False},
    "redis-cli":             {"apt": "redis-tools",                     "required": False},

    # Other services
    "rsync":                 {"apt": "rsync",                           "required": False},
    "showmount":             {"apt": "nfs-common",                      "required": False},
    "rpcinfo":               {"apt": "rpcbind",                         "required": False},
    "impacket-rpcdump":      {"apt": "python3-impacket",                "required": False},
    "smtp-user-enum":        {"apt": "smtp-user-enum",                  "required": False},
    "enum4linux-ng":         {"apt": "enum4linux-ng",                   "required": False},
    "ipmitool":              {"apt": "ipmitool",                        "required": False},

    # CMS scanners
    "joomscan":              {"apt": "joomscan",                        "required": False},
    "droopescan":            {"pip": "droopescan",                      "required": False},
    "cewl":                  {"apt": "cewl",                            "required": False},

    # Post-discovery
    "searchsploit":          {"apt": "exploitdb",                       "required": False},
    "openssl":               {"apt": "openssl",                         "required": False},
    "git-dumper":            {"pip": "git-dumper",                      "required": False},
}


def check_deps() -> set[str]:
    """
    Check for each tool. Prompt to install missing ones.
    Returns the set of available tool names so callers can skip absent ones.
    """
    missing_required: list[str] = []
    missing_optional: list[str] = []

    for tool, meta in TOOLS.items():
        if not shutil.which(tool):
            (missing_required if meta["required"] else missing_optional).append(tool)

    if missing_optional:
        print(f"[*] Optional tools missing: {', '.join(missing_optional)}")
        try:
            answer = input("    Install missing optional tools now? [Y/n] > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            answer = "n"
        if answer in ("", "y", "yes"):
            for tool in missing_optional:
                _install(tool, TOOLS[tool])

    if missing_required:
        print(f"\n[!] Required tools missing: {', '.join(missing_required)}")
        try:
            answer = input("    Attempt install now? [Y/n] > ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            answer = "n"
        if answer in ("", "y", "yes"):
            for tool in missing_required:
                _install(tool, TOOLS[tool])
            still_missing = [t for t in missing_required if not shutil.which(t)]
            if still_missing:
                print(f"[!] Still missing required tools: {', '.join(still_missing)}")
                sys.exit(1)
        else:
            sys.exit(1)

    available = {tool for tool in TOOLS if shutil.which(tool)}
    return available


def _install(tool: str, meta: dict):
    if "apt" in meta:
        _apt_install(meta["apt"], tool)
    elif "go" in meta:
        _go_install(meta["go"], tool)
    elif "pip" in meta:
        _pip_install(meta["pip"], tool)


def _apt_install(pkg: str, tool: str):
    print(f"    [apt] Installing {pkg}...")
    result = subprocess.run(["apt", "install", "-y", pkg], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"    [!] apt install {pkg} failed: {result.stderr.strip()}")
    else:
        print(f"    [+] Installed {tool}")


def _go_install(pkg: str, tool: str):
    if not shutil.which("go"):
        print(f"    [go] go not found — installing golang-go via apt...")
        r = subprocess.run(["apt", "install", "-y", "golang-go"],
                           capture_output=True, text=True)
        if r.returncode != 0 or not shutil.which("go"):
            print(f"    [!] golang-go install failed — cannot install {tool}")
            return
        print(f"    [+] Go installed")

    # Resolve GOPATH so we can find the binary after install
    gopath_result = subprocess.run(["go", "env", "GOPATH"],
                                   capture_output=True, text=True)
    gopath = gopath_result.stdout.strip() or str(Path.home() / "go")
    gobin = Path(gopath) / "bin"

    print(f"    [go] Installing {pkg}...")
    env = os.environ.copy()
    env["PATH"] = env.get("PATH", "") + f":{gobin}"
    result = subprocess.run(["go", "install", pkg],
                            capture_output=True, text=True, env=env)
    if result.returncode != 0:
        print(f"    [!] go install {pkg} failed: {result.stderr.strip()}")
        return

    # Symlink into /usr/local/bin so the tool is in PATH for this and future runs
    tool_bin = gobin / tool
    if tool_bin.exists():
        symlink = Path(f"/usr/local/bin/{tool}")
        if not symlink.exists():
            try:
                symlink.symlink_to(tool_bin)
            except OSError:
                pass  # already exists or no permission (shouldn't happen as root)
        print(f"    [+] Installed {tool}")
    else:
        print(f"    [!] go install succeeded but {tool} not found in {gobin}")


def _pip_install(pkg: str, tool: str):
    print(f"    [pip] Installing {pkg}...")
    # Try pipx first (cleaner for standalone tools), fall back to pip3
    for installer in (["pipx", "install"], ["pip3", "install", "--quiet"]):
        if shutil.which(installer[0]):
            result = subprocess.run([*installer, pkg], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"    [+] Installed {tool} via {installer[0]}")
                return
    print(f"    [!] pip install {pkg} failed — install manually: pip3 install {pkg}")
