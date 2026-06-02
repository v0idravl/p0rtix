"""
Scan state management.

Written after each major phase completes so --continue can skip already-finished
work. Stored at <machine_dir>/state.json.

Phases tracked:
  port_discovery  — full TCP + UDP nmap scan (slowest, most worth skipping)
  service_scan    — nmap version detection on open ports
  enumeration     — all parallel service/web handlers
  post_domain     — domain-gated checks (GetNPUsers, kerbrute)
  followup        — follow-up on discovered vhosts / SSL SANs
  complete        — entire scan finished cleanly
"""
import json
from datetime import datetime
from pathlib import Path


class ScanState:
    def __init__(self, machine_dir: Path):
        self._path = machine_dir / "state.json"
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except Exception:
                return {}
        return {}

    def _save(self):
        self._path.write_text(json.dumps(self._data, indent=2, default=str))

    @property
    def exists(self) -> bool:
        return self._path.exists() and bool(self._data.get("phases"))

    def is_done(self, phase: str) -> bool:
        return bool(self._data.get("phases", {}).get(phase))

    def mark_done(self, phase: str, **kwargs):
        """Mark a phase complete and optionally persist extra data (e.g. ports dict)."""
        self._data.setdefault("phases", {})[phase] = True
        self._data.update(kwargs)
        self._data["updated"] = datetime.now().isoformat()
        self._save()

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    @property
    def has_prior_scan(self) -> bool:
        """True if a previous unauthenticated scan completed port + service discovery."""
        return self.is_done("port_discovery") and self.is_done("service_scan")

    def completed_phases(self) -> list[str]:
        return [p for p, v in self._data.get("phases", {}).items() if v]

    def summary(self) -> str:
        done = self.completed_phases()
        return f"{len(done)} phase(s) done: {', '.join(done)}" if done else "no phases recorded"
