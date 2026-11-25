"""Log de auditoria append-only con cadena de hashes (tamper-evident).

Cada registro incluye el hash del anterior: si alguien edita o borra una linea,
`verify()` lo detecta.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = uuid.uuid4().hex[:12]
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def write(self, stage: str, subject: str, data: dict) -> None:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "stage": stage,
            "subject": subject,
            "data": data,
            "prev": self._prev,
        }
        payload = json.dumps(record, sort_keys=True, ensure_ascii=False, default=str)
        record["hash"] = hashlib.sha256(payload.encode()).hexdigest()
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        self._prev = record["hash"]


def verify(path: Path) -> tuple[bool, str]:
    prev = GENESIS
    with Path(path).open(encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            h = rec.pop("hash")
            if rec["prev"] != prev:
                return False, f"cadena rota en la linea {n}"
            payload = json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str)
            if hashlib.sha256(payload.encode()).hexdigest() != h:
                return False, f"registro alterado en la linea {n}"
            prev = h
    return True, "integridad OK"
