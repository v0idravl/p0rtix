import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

# Tool name → install instructions.
# "apt"     — installed with: apt install -y <pkg>
# "go"      — installed with: go install <pkg>
# "pip"     — installed with: pip3 install <pkg>
# "github"  — downloaded as a pre-built binary from GitHub releases
# required=True → abort if missing; False → skip gracefully
TOOLS: dict[str, dict] = {
    # Core — scan cannot run without these
    "nmap":                  {"apt": "nmap",                            "required": True},
    "curl":                  {"apt": "curl",                            "required": True},
    "ffuf":                  {"apt": "ffuf",                            "required": True},

    # Web
    "whatweb":               {"apt": "whatweb",                         "required": False},
    "gospider":              {"github": {"repo": "jaeles-project/gospider",  "pattern": "gospider_linux_{arch}.tar.gz",  "binary": "gospider"},  "required": False},
    # Debian/Kali ship the testssl.sh package's executable as plain `testssl`;
    # accept either name so detection + invocation work after an apt install.
    "testssl.sh":            {"apt": "testssl.sh", "bin": ["testssl", "testssl.sh"], "required": False},
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
    "certipy-ad":            {"pip": "certipy-ad",                      "required": False},
    "bloodyAD":              {"pip": "bloodyad",                        "required": False},

    # Kerberos
    "kerbrute":              {"github": {"repo": "ropnop/kerbrute",         "pattern": "kerbrute_linux_{arch}",     "binary": "kerbrute"},  "required": False},
    "impacket-GetNPUsers":   {"apt": "python3-impacket",                "required": False},
    "impacket-GetUserSPNs":  {"apt": "python3-impacket",                "required": False},
    "impacket-lookupsid":    {"apt": "python3-impacket",                "required": False},
    "impacket-secretsdump":  {"apt": "python3-impacket",                "required": False},
    "ntpdate":               {"apt": "ntpdate",                         "required": False},

    # Cracking
    "hashcat":               {"apt": "hashcat",                         "required": False},

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

    # CMS / web tools
    "arjun":                 {"pip": "arjun",                           "required": False},
    "joomscan":              {"apt": "joomscan",                        "required": False},
    "droopescan":            {"pip": "droopescan",                      "required": False},
    "cewl":                  {"apt": "cewl",                            "required": False},

    # Post-discovery
    "searchsploit":          {"apt": "exploitdb",                       "required": False},
    "openssl":               {"apt": "openssl",                         "required": False},
    "git-dumper":            {"pip": "git-dumper",                      "required": False},
    "anthropic":             {"pip": "anthropic", "library": True,       "required": False},
}


# Extended search path so sudo runs find pipx/pip binaries in user .local/bin
_SEARCH_PATH = os.environ.get("PATH", "") + ":/root/.local/bin:" + str(Path.home() / ".local/bin")


def _bin_candidates(tool: str, meta: dict) -> list[str]:
    """Executable name(s) to look for. Defaults to the tool key; a tool whose
    installed binary differs (e.g. testssl.sh → `testssl`) declares `bin`."""
    b = meta.get("bin")
    if not b:
        return [tool]
    return b if isinstance(b, list) else [b]


def _is_available(tool: str, meta: dict) -> bool:
    if meta.get("library"):
        return importlib.util.find_spec(tool) is not None
    return any(shutil.which(c, path=_SEARCH_PATH) for c in _bin_candidates(tool, meta))


def resolve_bin(tool: str) -> str:
    """
    Return the actual executable name for a tool key, resolving aliases (e.g.
    `testssl.sh` → `testssl` when that's what's on PATH). Callers invoke the
    returned name instead of hardcoding the tool key. Falls back to the key.
    """
    meta = TOOLS.get(tool, {})
    for c in _bin_candidates(tool, meta):
        if shutil.which(c, path=_SEARCH_PATH):
            return c
    return tool


def check_deps(install_missing: bool = True) -> set[str]:
    """
    Check for each tool and optionally prompt to install missing ones.
    Returns the set of available tool names so callers can skip absent ones.
    """
    missing_required: list[str] = []
    missing_optional: list[str] = []

    for tool, meta in TOOLS.items():
        if not _is_available(tool, meta):
            (missing_required if meta["required"] else missing_optional).append(tool)

    if missing_optional:
        print(f"[*] Optional tools missing: {', '.join(missing_optional)}")
        if install_missing and sys.stdin.isatty():
            try:
                answer = input("    Install missing optional tools now? [Y/n] > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                answer = "n"
            if answer in ("", "y", "yes"):
                for tool in missing_optional:
                    _install(tool, TOOLS[tool])
        elif install_missing:
            print("    non-interactive — skipping optional installs (steps needing them are skipped)")
        else:
            print("    --no-install set; optional tools will be skipped if needed")

    if missing_required:
        print(f"\n[!] Required tools missing: {', '.join(missing_required)}")
        if install_missing:
            if sys.stdin.isatty():
                try:
                    answer = input("    Attempt install now? [Y/n] > ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print()
                    answer = "n"
            else:
                # Non-interactive: required tools are needed to scan at all, so
                # attempt install rather than aborting on a prompt no one answers.
                print("    non-interactive — attempting required-tool install")
                answer = "y"
            if answer in ("", "y", "yes"):
                for tool in missing_required:
                    _install(tool, TOOLS[tool])
                still_missing = [t for t in missing_required if not shutil.which(t)]
                if still_missing:
                    print(f"[!] Still missing required tools: {', '.join(still_missing)}")
                    sys.exit(1)
            else:
                sys.exit(1)
        else:
            print("    --no-install set; install required tools manually and re-run")
            sys.exit(1)

    available = {tool for tool, meta in TOOLS.items() if _is_available(tool, meta)}
    return available


def _install(tool: str, meta: dict):
    if "apt" in meta:
        _apt_install(meta["apt"], tool)
    elif "github" in meta:
        _github_install(tool, **meta["github"])
    elif "go" in meta:
        _go_install(meta["go"], tool)
    elif "pip" in meta:
        _pip_install(meta["pip"], tool, library=meta.get("library", False))


def _github_install(tool: str, repo: str, pattern: str, binary: str):
    """Download a pre-built binary from the latest GitHub release."""
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(machine, machine)
    # Projects name their 64-bit Linux assets inconsistently (amd64 vs x86_64,
    # arm64 vs aarch64). Match on any alias for our arch.
    arch_aliases = {
        "amd64": ("amd64", "x86_64", "x64"),
        "arm64": ("arm64", "aarch64"),
    }.get(arch, (arch,))
    filename = pattern.format(arch=arch)
    dest = Path(f"/usr/local/bin/{tool}")

    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    print(f"    [github] Installing {tool} from {repo}...")
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "p0rtix"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            release = json.loads(resp.read())

        assets = release.get("assets", [])
        asset = next((a for a in assets if a["name"] == filename), None)
        if asset is None:
            # Alias-aware fallback: a Linux asset for our arch, excluding other
            # OSes and 32-bit builds (i386 / bare "arm").
            _other_os = ("darwin", "macos", "windows", "freebsd", "openbsd", ".exe")
            def _matches(name: str) -> bool:
                n = name.lower()
                if "linux" not in n or any(o in n for o in _other_os):
                    return False
                return any(a in n for a in arch_aliases)
            asset = next((a for a in assets if _matches(a["name"])), None)
        if asset is None:
            print(f"    [!] No matching release asset for {filename} in {repo}")
            return

        download_url = asset["browser_download_url"]
        tmp = Path(f"/tmp/{asset['name']}")
        urllib.request.urlretrieve(download_url, tmp)

        if tmp.suffix == ".zip":
            with zipfile.ZipFile(tmp) as z:
                names = z.namelist()
                target = next((n for n in names if Path(n).name == binary), names[0])
                extracted = Path("/tmp") / Path(target).name
                with z.open(target) as src, open(extracted, "wb") as out:
                    out.write(src.read())
            tmp.unlink()
            tmp = extracted
        elif tmp.name.endswith(".tar.gz") or tmp.suffix in (".tgz",):
            with tarfile.open(tmp) as t:
                names = t.getnames()
                target = next((n for n in names if Path(n).name == binary), names[0])
                member = t.getmember(target)
                with t.extractfile(member) as src:
                    extracted = Path("/tmp") / Path(target).name
                    extracted.write_bytes(src.read())
            tmp.unlink()
            tmp = extracted

        # /usr/local/bin needs root; p0rtix runs unprivileged (nmap caps), so
        # fall back to ~/.local/bin (already on the detection search path).
        try:
            dest.write_bytes(tmp.read_bytes())
        except PermissionError:
            dest = Path.home() / ".local/bin" / tool
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(tmp.read_bytes())
        dest.chmod(0o755)
        tmp.unlink(missing_ok=True)
        print(f"    [+] Installed {tool} → {dest}")

    except Exception as exc:
        print(f"    [!] GitHub install failed for {tool}: {exc}")


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


def _symlink_pipx(tool: str) -> None:
    """Symlink a pipx-installed binary into /usr/local/bin so sudo PATH finds it."""
    for base in (Path("/root/.local/bin"), Path.home() / ".local/bin"):
        candidate = base / tool
        if candidate.exists():
            symlink = Path(f"/usr/local/bin/{tool}")
            if not symlink.exists():
                try:
                    symlink.symlink_to(candidate)
                except OSError:
                    pass
            return


def _pip_install(pkg: str, tool: str, library: bool = False) -> None:
    print(f"    [pip] Installing {pkg}...")

    if library:
        # Libraries must be importable in the running interpreter — skip pipx
        for cmd in (
            ["pip3", "install", "--quiet", pkg],
            ["pip3", "install", "--quiet", "--break-system-packages", pkg],
        ):
            if shutil.which(cmd[0]):
                result = subprocess.run(cmd, capture_output=True, text=True)
                if result.returncode == 0:
                    print(f"    [+] Installed {tool}")
                    return
        print(f"    [!] pip install {pkg} failed — install manually: pip3 install {pkg}")
        return

    # CLI tools: try pipx first (isolated env), fall back to pip3
    for installer in (["pipx", "install"], ["pip3", "install", "--quiet"]):
        if shutil.which(installer[0]):
            result = subprocess.run([*installer, pkg], capture_output=True, text=True)
            if result.returncode == 0:
                if installer[0] == "pipx":
                    _symlink_pipx(tool)
                print(f"    [+] Installed {tool} via {installer[0]}")
                return
    print(f"    [!] pip install {pkg} failed — install manually: pip3 install {pkg}")
