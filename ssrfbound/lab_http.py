"""In-process lab HTTP servers reached only by IP and port."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from ssrfbound.errors import LabUnreachable


@dataclass
class LabResponse:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


class LabHttp:
    """Serve fixture routes. Routing is by destination IP, port, and path.

    The Host header is not used for routing. There is no real network I/O.
    """

    def __init__(self, data: dict[str, Any]):
        self._routes: dict[tuple[str, int, str], dict[str, Any]] = {}
        for server in data.get("servers") or []:
            ip = str(server["ip"])
            port = int(server["port"])
            for route in server.get("routes") or []:
                path = route["path"]
                self._routes[(ip, port, path)] = route

    @classmethod
    def from_file(cls, path: str | Path) -> "LabHttp":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data)

    def request(
        self,
        ip: str,
        port: int,
        method: str = "GET",
        path: str = "/",
        headers: Mapping[str, str] | None = None,
    ) -> LabResponse:
        del method, headers  # fixtures are GET-only in this snapshot
        route = self._routes.get((str(ip), int(port), path))
        if route is None:
            # A known host with a missing path still counts as reachable 404
            known = any(k[0] == str(ip) and k[1] == int(port) for k in self._routes)
            if not known:
                raise LabUnreachable(str(ip), int(port))
            return LabResponse(status=404, headers={"Content-Type": "text/plain"}, body=b"not found")
        body = route.get("body", "")
        if isinstance(body, str):
            raw = body.encode("utf-8")
        else:
            raw = bytes(body)
        headers = {str(k): str(v) for k, v in (route.get("headers") or {}).items()}
        return LabResponse(status=int(route["status"]), headers=headers, body=raw)
