"""Deterministic lab DNS. Some names change records across successive lookups."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

try:
    import idna
except ImportError:  # pragma: no cover
    idna = None

from ssrfbound.errors import LabNxDomain


def _fold_name(name: str) -> str:
    n = name.strip().rstrip(".").lower()
    if idna is not None:
        try:
            n = idna.encode(n).decode("ascii")
        except Exception:
            pass
    return n


class LabResolver:
    """In-process resolver backed by fixtures/lab_dns.json.

    For names with a ``sequence`` of answers, each ``resolve`` call advances
    one step and then stays on the last answer (it does not wrap around).
    """

    def __init__(self, data: dict[str, Any]):
        records = data.get("records") or {}
        self._records: dict[str, Any] = {}
        for name, rec in records.items():
            self._records[_fold_name(name)] = rec
        self._seq: dict[str, int] = {}

    @classmethod
    def from_file(cls, path: str | Path) -> "LabResolver":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data)

    def resolve(self, name: str) -> list[str]:
        key = _fold_name(name)
        rec = self._records.get(key)
        if rec is None:
            raise LabNxDomain(name)
        if "sequence" in rec:
            answers = rec["sequence"]
            if not answers:
                raise LabNxDomain(name)
            i = self._seq.get(key, 0)
            slot = answers[i] if i < len(answers) else answers[-1]
            self._seq[key] = i + 1
            return _addrs(slot)
        return _addrs(rec)


def _addrs(slot: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for key in ("a", "aaaa"):
        for item in slot.get(key) or []:
            out.append(str(item))
    return out
