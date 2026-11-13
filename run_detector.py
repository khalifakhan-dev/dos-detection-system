from __future__ import annotations

import argparse
import contextlib
import os
import sys
import logging
import threading

import uvicorn

from api.app import app, runtime
from configuration.loader import load_config, resolve_path
from detector.detector_service import DetectorService
from storage.database import Database


@contextlib.contextmanager
def single_instance_lock(lock_path):
    """Prevent two detector processes from owning one capture/API/firewall runtime."""
    if os.name != "posix":
        raise RuntimeError("Detector backend requires Linux/POSIX for its nftables integration")
    import fcntl
    from pathlib import Path
    path = Path(lock_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+") as lock_file:
        try:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError("Another detector instance is already running (instance lock held)") from exc
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def configure_logging(config: dict) -> None:
    logging_cfg = config.get("logging", {})
    level = getattr(logging, str(logging_cfg.get("level", "INFO")).upper(), logging.INFO)
    log_path = resolve_path(config, logging_cfg.get("file", "logs/dos_detector.log"))
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s", handlers=[logging.StreamHandler(), logging.FileHandler(log_path)])


def main() -> None:
    parser = argparse.ArgumentParser(description="Real-time threshold-based DoS detector")
    parser.add_argument("--config", default=None, help="Path to YAML configuration")
    parser.add_argument("--no-capture", action="store_true", help="Start API/runtime without packet capture, useful for API smoke tests")
    args = parser.parse_args()
    config = load_config(args.config)
    configure_logging(config)
    database_path = resolve_path(config, config.get("storage", {}).get("database_path", "logs/dos_detection.sqlite3"))
    lock_path = database_path.with_suffix(database_path.suffix + ".lock")
    try:
        with single_instance_lock(lock_path):
            database = Database(database_path)
            service = DetectorService(config, database)
            runtime.config = config
            runtime.service = service
            try:
                service.start(capture=not args.no_capture)
                api_cfg = config.get("api", {})
                server = uvicorn.Server(uvicorn.Config(app, host=api_cfg.get("host", "0.0.0.0"), port=int(api_cfg.get("port", 8000)), log_level="info"))
                try:
                    server.run()
                except KeyboardInterrupt:
                    logging.info("Detector interrupted; shutting down")
            finally:
                service.stop()
                runtime.service = None
    except RuntimeError as exc:
        logging.error("Detector startup refused: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
