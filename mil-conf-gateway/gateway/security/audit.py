"""Structured audit logger — one JSON line per event.

Required by most military accreditation schemes: every REGISTER, INVITE,
BYE, and floor grant/revoke is written to a tamper-evident append-only
file with a monotonic sequence number and UTC ISO-8601 timestamp.
"""
from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq = 0
        self._lock = threading.Lock()
        # append-only, line-buffered
        self._fp = open(self.path, "a", buffering=1, encoding="utf-8")

    def log(self, event: str, **fields) -> None:
        with self._lock:
            self._seq += 1
            record = {
                "seq": self._seq,
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **fields,
            }
            self._fp.write(json.dumps(record, ensure_ascii=True) + "\n")

    def close(self) -> None:
        try:
            self._fp.flush()
            os.fsync(self._fp.fileno())
        finally:
            self._fp.close()
