"""Journal d'incidents structuré (JSON Lines), exploitable par le dashboard et le rapport."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class SecurityLogger:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else None
        self._mem: list[dict] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, *, mode: str, layer: str, rule: str, query: str, detail: str = "") -> dict:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mode": mode,
            "layer": layer,
            "rule": rule,
            "query": query[:120],
            "detail": detail[:160],
        }
        self._mem.append(event)
        if self.path:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def read(self) -> list[dict]:
        if self.path and self.path.exists():
            with self.path.open(encoding="utf-8") as f:
                return [json.loads(line) for line in f if line.strip()]
        return list(self._mem)

    def clear(self) -> None:
        self._mem.clear()
        if self.path and self.path.exists():
            self.path.unlink()
