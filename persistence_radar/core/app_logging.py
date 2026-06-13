from __future__ import annotations

from pathlib import Path
import logging
import os
import sys
import traceback

DEFAULT_LOG_DIR = Path.home() / "Library" / "Logs" / "macOSPersistenceRadar"
FALLBACK_LOG_DIR = Path(os.environ.get("TMPDIR", "/tmp")) / "macOSPersistenceRadar" / "Logs"
LOG_DIR = DEFAULT_LOG_DIR
LOG_FILE = LOG_DIR / "radar.log"


def setup_logging() -> Path:
    global LOG_DIR, LOG_FILE
    for candidate in (DEFAULT_LOG_DIR, FALLBACK_LOG_DIR):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            LOG_DIR = candidate
            LOG_FILE = LOG_DIR / "radar.log"
            logging.basicConfig(
                filename=LOG_FILE,
                level=logging.INFO,
                format="%(asctime)s %(levelname)s %(name)s: %(message)s",
                force=True,
            )
            return LOG_FILE
        except OSError:
            continue
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", force=True)
    return LOG_FILE


def get_log_dir() -> Path:
    return LOG_DIR


def install_global_exception_hook() -> None:
    setup_logging()

    def handle(exc_type, exc_value, exc_traceback):
        logging.critical(
            "Unhandled exception\n%s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_traceback)),
        )
        sys.__excepthook__(exc_type, exc_value, exc_traceback)

    sys.excepthook = handle
