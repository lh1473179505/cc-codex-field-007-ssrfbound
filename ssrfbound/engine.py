"""Fail-closed SSRF admission and pinned-IP fetch against the lab network."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from ssrfbound.errors import LabNxDomain
from ssrfbound.lab_dns import LabResolver
from ssrfbound.lab_http import LabHttp
from ssrfbound.policy import Policy

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_DEFAULT_PORTS = {"http": 80, "https": 443}

# Specific reason codes for the well-known blocked ranges. Any other
# blocked CIDR falls back to "multicast_or_reserved".
_REASON_BY_CIDR = {
    "127.0.0.0/8": "loopback",
    "::1/128": "loopback",
    "10.0.0.0/8": "private",
    "172.16.0.0/12": "private",
    "192.168.0.0/16": "private",
    "fc00::/7": "private",
    "169.254.0.0/16": "link_local",
    "fe80::/10": "link_local",
    "0.0.0.0/8": "unspecified",
    "::/128": "unspecified",
}

_V4_COMPAT_PREFIX = ipaddress.IPv6Network("::/96")
_NAT64_PREFIX = ipaddress.IPv6Network("64:ff9b::/96")
_6TO4_PREFIX = ipaddress.IPv6Network("2002::/16")


@dataclass
class _ResolveCtx:
    resolved: list[dict[str, Any]] = field(default_factory=list)
    lookup_seq: dict[str, int] = field(default_factory=dict)


@dataclass
class _Admission:
    allow: bool
    reason_codes: list[str]
    parsed: dict[str, Any]
    pinned_ip: str | None = None
    host: str | None = None
    port: int | None = None
    path: str = "/"


def _dedupe(codes: list[str]) -> list[str]:
    return list(dict.fromkeys(codes))


def _parse_ipv4_literal(host: str) -> ipaddress.IPv4Address | None:
    """Parse inet_aton-style IPv4 literals: dotted quad, short forms,
    plain decimal, octal (leading 0) and hex (0x) parts."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums: list[int] = []
    for part in parts:
        if not part:
            return None
        if part[:2].lower() == "0x":
            digits = part[2:]
            if not digits or any(c not in "0123456789abcdefABCDEF" for c in digits):
                return None
            nums.append(int(digits, 16))
        elif len(part) > 1 and part[0] == "0":
            if any(c not in "01234567" for c in part):
                return None
            nums.append(int(part, 8))
        else:
            if any(c not in "0123456789" for c in part):
                return None
            nums.append(int(part, 10))
    if len(nums) == 1:
        if nums[0] > 0xFFFFFFFF:
            return None
        value = nums[0]
    else:
        head, last = nums[:-1], nums[-1]
        if any(h > 0xFF for h in head):
            return None
        last_bits = 8 * (4 - len(head))
        if last >= (1 << last_bits):
            return None
        value = 0
        for h in head:
            value = (value << 8) | h
        value = (value << last_bits) | last
    return ipaddress.IPv4Address(value)


def _effective_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Unwrap IPv4 addresses embedded in IPv6 transition forms."""
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            return mapped
        if ip in _V4_COMPAT_PREFIX and int(ip) > 1:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip in _NAT64_PREFIX:
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if ip in _6TO4_PREFIX:
            return ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
    return ip


def _parse_ip_literal(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if ":" in host:
        try:
            return _effective_ip(ipaddress.IPv6Address(host))
        except ValueError:
            return None
    return _parse_ipv4_literal(host)


def _policy_nets(
    policy: Policy,
) -> tuple[list[tuple[Any, str]], list[Any]]:
    blocked: list[tuple[Any, str]] = []
    for cidr in policy.blocked_cidrs:
        net = ipaddress.ip_network(cidr)
        blocked.append((net, _REASON_BY_CIDR.get(str(net), "multicast_or_reserved")))
    public = [ipaddress.ip_network(c) for c in policy.lab_public_cidrs]
    return blocked, public


def _classify(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    policy: Policy,
    blocked: list[tuple[Any, str]],
) -> list[str]:
    codes: list[str] = []
    if ip.version == 4 and str(ip) in policy.metadata_ipv4:
        codes.append("metadata")
    for net, reason in blocked:
        if ip.version == net.version and ip in net:
            codes.append(reason)
            break
    return codes


def _in_nets(ip: Any, nets: list[Any]) -> bool:
    return any(ip.version == net.version and ip in net for net in nets)


def _admit(
    url: str,
    policy: Policy,
    resolver: LabResolver,
    ctx: _ResolveCtx,
    blocked: list[tuple[Any, str]],
    public: list[Any],
) -> _Admission:
    parsed: dict[str, Any] = {"scheme": None, "host": None, "port": None, "userinfo": False}
    try:
        parts = urlsplit(url)
    except ValueError:
        return _Admission(False, ["invalid_url"], parsed)
    scheme = (parts.scheme or "").lower()
    parsed["scheme"] = scheme or None
    if not scheme:
        return _Admission(False, ["invalid_url"], parsed)
    if scheme not in _DEFAULT_PORTS:
        return _Admission(False, ["blocked_scheme"], parsed)
    parsed["userinfo"] = "@" in parts.netloc
    try:
        host = parts.hostname
        explicit_port = parts.port
    except ValueError:
        return _Admission(False, ["invalid_url"], parsed)
    if not host:
        return _Admission(False, ["invalid_url"], parsed)
    host = host.rstrip(".").lower()
    parsed["host"] = host
    port = explicit_port if explicit_port is not None else _DEFAULT_PORTS[scheme]
    parsed["port"] = port
    if port not in policy.allowed_ports:
        return _Admission(False, ["blocked_port"], parsed)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    blocked_host = policy.hostname_blocked(host)
    if blocked_host is not None:
        return _Admission(False, [blocked_host], parsed)

    literal = _parse_ip_literal(host)
    if literal is not None:
        codes = _classify(literal, policy, blocked)
        if codes:
            return _Admission(False, codes, parsed)
        if not _in_nets(literal, public):
            return _Admission(False, ["not_lab_public"], parsed)
        return _Admission(True, [], parsed, pinned_ip=str(literal), host=host, port=port, path=path)

    try:
        answers = resolver.resolve(host)
    except LabNxDomain:
        return _Admission(False, ["nxdomain"], parsed)
    seq = ctx.lookup_seq.get(host, 0) + 1
    ctx.lookup_seq[host] = seq
    ctx.resolved.append({"host": host, "addresses": list(answers), "lookup_seq": seq})
    if not answers:
        return _Admission(False, ["nxdomain"], parsed)

    codes = []
    any_blocked = False
    any_public = False
    effective: list[Any] = []
    for answer in answers:
        ip = _parse_ip_literal(str(answer))
        if ip is None:
            codes.append("not_lab_public")
            continue
        effective.append(ip)
        addr_codes = _classify(ip, policy, blocked)
        if addr_codes:
            any_blocked = True
            codes.extend(addr_codes)
        elif _in_nets(ip, public):
            any_public = True
        else:
            codes.append("not_lab_public")
    if any_blocked:
        out = _dedupe(codes)
        if any_public:
            out.append("mixed_blocked_records")
        return _Admission(False, out, parsed)
    if codes:
        return _Admission(False, _dedupe(codes), parsed)
    return _Admission(True, [], parsed, pinned_ip=str(effective[0]), host=host, port=port, path=path)


def check_url(url: str, policy: Policy, resolver: LabResolver) -> dict[str, Any]:
    blocked, public = _policy_nets(policy)
    ctx = _ResolveCtx()
    adm = _admit(url, policy, resolver, ctx, blocked, public)
    return {
        "url": url,
        "decision": "allow" if adm.allow else "deny",
        "reason_codes": [] if adm.allow else adm.reason_codes,
        "parsed": adm.parsed,
        "resolved": ctx.resolved,
        "pinned_ip": adm.pinned_ip if adm.allow else None,
        "redirect_chain": [],
        "fetch": None,
    }


def _location(headers: dict[str, str]) -> str | None:
    for key, value in headers.items():
        if key.lower() == "location":
            return value
    return None


def fetch_url(
    url: str,
    policy: Policy,
    resolver: LabResolver,
    http: LabHttp,
    out_path: str | Path | None,
) -> dict[str, Any]:
    blocked, public = _policy_nets(policy)
    ctx = _ResolveCtx()
    chain: list[dict[str, Any]] = []
    parsed: dict[str, Any] = {"scheme": None, "host": None, "port": None, "userinfo": False}
    pinned_ip: str | None = None
    reason_codes: list[str] = []
    decision = "deny"
    fetch_info: dict[str, Any] | None = None
    wrote_out = False

    current = url
    redirects_left = policy.max_redirects
    first_hop = True
    while True:
        adm = _admit(current, policy, resolver, ctx, blocked, public)
        if first_hop:
            parsed = adm.parsed
            first_hop = False
        if not adm.allow:
            reason_codes = list(adm.reason_codes)
            if chain:
                chain[-1]["decision"] = "deny"
                reason_codes = _dedupe(reason_codes + ["redirect_to_blocked"])
            break
        pinned_ip = adm.pinned_ip
        resp = http.request(adm.pinned_ip, adm.port, "GET", adm.path, {"Host": adm.host or ""})
        location = _location(resp.headers)
        if resp.status in _REDIRECT_STATUSES and location:
            hop = {"from": current, "status": resp.status, "location": location, "decision": "allow"}
            chain.append(hop)
            if redirects_left <= 0:
                hop["decision"] = "deny"
                reason_codes = ["too_many_redirects"]
                break
            redirects_left -= 1
            current = urljoin(current, location)
            continue
        decision = "allow"
        if out_path is not None:
            out = Path(out_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(resp.body)
            wrote_out = True
        fetch_info = {
            "status": resp.status,
            "bytes": len(resp.body),
            "path": str(out_path) if out_path is not None else None,
        }
        break

    if decision == "deny" and wrote_out and out_path is not None:
        try:
            Path(out_path).unlink()
        except OSError:
            pass

    return {
        "url": url,
        "decision": decision,
        "reason_codes": reason_codes if decision == "deny" else [],
        "parsed": parsed,
        "resolved": ctx.resolved,
        "pinned_ip": pinned_ip,
        "redirect_chain": chain,
        "fetch": fetch_info,
    }
