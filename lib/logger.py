import logging
import sys
from pathlib import Path

_LOGGER_NAME = "p0rtix"
_fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")


def setup_logging(log_dir: Path) -> None:
    log_dir.mkdir(parents=True, exist_ok=True)

    log = logging.getLogger(_LOGGER_NAME)
    log.setLevel(logging.DEBUG)
    if log.handlers:
        return  # already configured (e.g. combined scan+creds mode)

    def _fh(name: str, level: int) -> logging.FileHandler:
        h = logging.FileHandler(log_dir / name, encoding="utf-8")
        h.setLevel(level)
        h.setFormatter(_fmt)
        return h

    log.addHandler(_fh("debug.log",  logging.DEBUG))
    log.addHandler(_fh("p0rtix.log", logging.INFO))
    log.addHandler(_fh("errors.log", logging.WARNING))

    # Console: only ERROR and above (print() handles the operator UI)
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.ERROR)
    ch.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    log.addHandler(ch)

    log.info("=" * 60)
    log.info("Session start")


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)
