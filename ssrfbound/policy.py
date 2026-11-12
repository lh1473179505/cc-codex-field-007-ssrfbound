"""Load the admission policy. Classification of unusual IP literals is not done here."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Policy:
    allowed_ports: tuple[int, ...]
    blocked_schemes: tuple[str, ...]
    blocked_cidrs: tuple[str, ...]
    lab_public_cidrs: tuple[str, ...]
    blocked_hostnames: tuple[str, ...]
    blocked_hostname_suffixes: tuple[str, ...]
    metadata_ipv4: tuple[str, ...]
    max_redirects: int
    raw: dict[str, Any]

    def hostname_blocked(self, host: str) -> str | None:
        """Return a reason code if the hostname itself is blocked, else None.

        This only looks at the literal hostname / suffix list. It does not
        resolve DNS or parse unusual IP literals.
        """
        h = host.strip().rstrip(".").lower()
        blocked = {n.strip().rstrip(".").lower() for n in self.blocked_hostnames}
        if h in blocked:
            return "blocked_hostname"
        for suf in self.blocked_hostname_suffixes:
            s = suf.strip().lower()
            if not s:
                continue
            if not s.startswith("."):
                s = "." + s
            if h.endswith(s) or h == s[1:]:
                return "blocked_suffix"
        return None


def load_policy(path: str | Path) -> Policy:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return Policy(
        allowed_ports=tuple(int(x) for x in raw["allowed_ports"]),
        blocked_schemes=tuple(s.lower() for s in raw["blocked_schemes"]),
        blocked_cidrs=tuple(raw["blocked_cidrs"]),
        lab_public_cidrs=tuple(raw["lab_public_cidrs"]),
        blocked_hostnames=tuple(raw["blocked_hostnames"]),
        blocked_hostname_suffixes=tuple(raw["blocked_hostname_suffixes"]),
        metadata_ipv4=tuple(raw["metadata_ipv4"]),
        max_redirects=int(raw["max_redirects"]),
        raw=raw,
    )
