"""JSON audit logger for attack sessions."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AttackLogger:
    """Collects statistics and writes a single JSON record per attack run."""

    def __init__(self, module_name: str, parameters: dict[str, Any], log_dir: str | Path = "logs"):
        self.module_name = module_name
        self.parameters = parameters
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.start_ts: float | None = None
        self.end_ts: float | None = None
        self.packets_sent: int = 0
        self.bytes_sent: int = 0
        self.status: str = "running"
        self.error_message: str | None = None

        self._file_path: Path | None = None

    def start(self) -> None:
        self.start_ts = time.time()
        self.status = "running"

    def stop(self, status: str = "completed") -> None:
        self.end_ts = time.time()
        self.status = status
        self._write()

    def error(self, message: str) -> None:
        self.error_message = message
        self.stop(status="error")

    def add_packets(self, count: int, bytes_count: int = 0) -> None:
        self.packets_sent += count
        self.bytes_sent += bytes_count

    def _write(self) -> None:
        if self.start_ts is None:
            return

        end = self.end_ts or time.time()
        duration = round(end - self.start_ts, 3)

        record = {
            "timestamp_start": datetime.fromtimestamp(
                self.start_ts, tz=timezone.utc
            ).isoformat(),
            "timestamp_end": datetime.fromtimestamp(end, tz=timezone.utc).isoformat(),
            "module": self.module_name,
            "parameters": self.parameters,
            "packets_sent": self.packets_sent,
            "bytes_sent": self.bytes_sent,
            "duration_sec": duration,
            "status": self.status,
        }
        if self.error_message:
            record["error"] = self.error_message

        # Filename: 20261018_171500_arp_spoof.json
        ts_str = datetime.fromtimestamp(self.start_ts).strftime("%Y%m%d_%H%M%S")
        safe_name = self.module_name.replace(" ", "_").lower()
        self._file_path = self.log_dir / f"{ts_str}_{safe_name}.json"

        with open(self._file_path, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)

    @property
    def path(self) -> Path | None:
        return self._file_path
