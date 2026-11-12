"""Admission and fetch engine. Not implemented in this snapshot."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ssrfbound.lab_dns import LabResolver
from ssrfbound.lab_http import LabHttp
from ssrfbound.policy import Policy


def check_url(url: str, policy: Policy, resolver: LabResolver) -> dict[str, Any]:
    raise NotImplementedError(
        "ssrfbound.check is not implemented in this snapshot"
    )


def fetch_url(
    url: str,
    policy: Policy,
    resolver: LabResolver,
    http: LabHttp,
    out_path: str | Path | None,
) -> dict[str, Any]:
    raise NotImplementedError(
        "ssrfbound.fetch is not implemented in this snapshot"
    )
