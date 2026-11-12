"""Fail-closed SSRF admission and pinned-IP fetch engine."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

try:
    import idna
except ImportError:  # pragma: no cover
    idna = None

from ssrfbound.errors import LabNxDomain, LabUnreachable
from ssrfbound.lab_dns import LabResolver
from ssrfbound.lab_http import LabHttp
from ssrfbound.policy import Policy

REDIRECT_STATUSES = {301, 302, 303, 307, 308}

_V4_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")
_V4_PRIVATE = tuple(ipaddress.ip_network(c) for c in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_V4_LINK_LOCAL = ipaddress.ip_network("169.254.0.0/16")
_V4_UNSPECIFIED = ipaddress.ip_network("0.0.0.0/8")
_V4_MULTICAST = ipaddress.ip_network("224.0.0.0/4")
_V4_BROADCAST = ipaddress.ip_address("255.255.255.255")
_V6_LOOPBACK = ipaddress.ip_address("::1")
_V6_PRIVATE = ipaddress.ip_network("fc00::/7")
_V6_LINK_LOCAL = ipaddress.ip_network("fe80::/10")
_V6_UNSPECIFIED = ipaddress.ip_address("::")
_V6_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_V6_6TO4 = ipaddress.ip_network("2002::/16")


def _fold_name(name: str) -> str:
    n = name.strip().rstrip(".").lower()
    if idna is not None:
        try:
            n = idna.encode(n).decode("ascii")
        except Exception:
            pass
    return n


def _parse_ipv4_literal(host: str) -> ipaddress.IPv4Address | None:
    """Parse inet_aton-style IPv4 literals: dotted, short, decimal, octal, hex.

    Returns None when the string is not a fully numeric literal (i.e. it
    should be treated as a hostname instead).
    """
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    numbers: list[int] = []
    for part in parts:
        if not part:
            return None
        try:
            if part.lower().startswith("0x"):
                value = int(part, 16)
            elif len(part) > 1 and part.startswith("0"):
                value = int(part, 8)
            else:
                value = int(part, 10)
        except ValueError:
            return None
        if value < 0:
            return None
        numbers.append(value)
    for value in numbers[:-1]:
        if value > 0xFF:
            return None
    if numbers[-1] >= 1 << (8 * (5 - len(numbers))):
        return None
    packed = 0
    for value in numbers[:-1]:
        packed = (packed << 8) | value
    packed = (packed << (8 * (5 - len(numbers)))) | numbers[-1]
    return ipaddress.IPv4Address(packed)


def _extract_embedded_ipv4(
    addr: ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """Pull an embedded IPv4 out of mapped / compatible / NAT64 / 6to4 forms."""
    mapped = addr.ipv4_mapped
    if mapped is not None:
        return mapped
    value = int(addr)
    if addr in _V6_NAT64:
        return ipaddress.IPv4Address(value & 0xFFFFFFFF)
    if addr in _V6_6TO4:
        return ipaddress.IPv4Address((value >> 80) & 0xFFFFFFFF)
    if value >> 32 == 0 and addr not in (_V6_UNSPECIFIED, _V6_LOOPBACK):
        # IPv4-compatible ::a.b.c.d
        return ipaddress.IPv4Address(value & 0xFFFFFFFF)
    return None


def _classify(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address, policy: Policy
) -> tuple[set[str], bool]:
    """Return (blocking reason codes, is_lab_public) for one address."""
    codes: set[str] = set()
    if isinstance(ip, ipaddress.IPv4Address):
        if str(ip) in policy.metadata_ipv4:
            codes.add("metadata")
        if ip in _V4_LOOPBACK:
            codes.add("loopback")
        if any(ip in net for net in _V4_PRIVATE):
            codes.add("private")
        if ip in _V4_LINK_LOCAL:
            codes.add("link_local")
        if ip in _V4_UNSPECIFIED:
            codes.add("unspecified")
        if ip in _V4_MULTICAST or ip == _V4_BROADCAST:
            codes.add("multicast_or_reserved")
    else:
        if ip == _V6_LOOPBACK:
            codes.add("loopback")
        if ip in _V6_PRIVATE:
            codes.add("private")
        if ip in _V6_LINK_LOCAL:
            codes.add("link_local")
        if ip == _V6_UNSPECIFIED:
            codes.add("unspecified")
        if ip.is_multicast:
            codes.add("multicast_or_reserved")
    if not codes:
        for cidr in policy.blocked_cidrs:
            if ip in ipaddress.ip_network(cidr):
                codes.add("multicast_or_reserved")
                break
    if codes:
        return codes, False
    for cidr in policy.lab_public_cidrs:
        if ip in ipaddress.ip_network(cidr):
            return codes, True
    return {"not_lab_public"}, False


def _normalize_literal(
    host: str, bracketed: bool
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Normalize an IP literal host to the address used for classification.

    Returns None when the host is not a literal and must go through DNS.
    Raises ValueError for a bracketed host that is not valid IPv6.
    """
    if bracketed:
        addr6 = ipaddress.IPv6Address(host)
        embedded = _extract_embedded_ipv4(addr6)
        return embedded if embedded is not None else addr6
    if ":" in host:
        addr6 = ipaddress.IPv6Address(host)
        embedded = _extract_embedded_ipv4(addr6)
        return embedded if embedded is not None else addr6
    return _parse_ipv4_literal(host)


@dataclass
class _Parsed:
    scheme: str | None
    host: str | None
    port: int | None
    userinfo: bool
    path: str
    bracketed: bool = False

    def as_report(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "host": self.host,
            "port": self.port,
            "userinfo": self.userinfo,
        }


@dataclass
class _Admission:
    allowed: bool
    codes: set[str]
    parsed: _Parsed
    pinned_ip: str | None = None


@dataclass
class _State:
    resolved: list[dict[str, Any]] = field(default_factory=list)
    lookup_seq: dict[str, int] = field(default_factory=dict)


def _parse_url(url: str) -> _Parsed:
    split = urlsplit(url)
    scheme = split.scheme.lower() or None
    netloc = split.netloc
    userinfo = "@" in netloc
    hostport = netloc.rsplit("@", 1)[-1]
    bracketed = hostport.startswith("[")
    host = split.hostname  # lowercases, strips brackets, keeps trailing dot
    port: int | None
    try:
        port = split.port
    except ValueError:
        port = None
    if port is None and scheme in ("http", "https"):
        port = 80 if scheme == "http" else 443
    path = split.path or "/"
    return _Parsed(scheme=scheme, host=host, port=port, userinfo=userinfo, path=path, bracketed=bracketed)


def _admit(url: str, policy: Policy, resolver: LabResolver, state: _State) -> _Admission:
    try:
        parsed = _parse_url(url)
    except ValueError:
        return _Admission(False, {"invalid_url"}, _Parsed(None, None, None, False, "/"))

    def deny(codes: set[str]) -> _Admission:
        return _Admission(False, codes, parsed)

    scheme = parsed.scheme
    if scheme is None:
        return deny({"invalid_url"})
    if scheme not in ("http", "https") or scheme in policy.blocked_schemes:
        return deny({"blocked_scheme"})
    if parsed.host is None or parsed.host == "":
        return deny({"invalid_url"})
    if parsed.port is None:
        return deny({"invalid_url"})
    if parsed.port not in policy.allowed_ports:
        return deny({"blocked_port"})

    folded = _fold_name(parsed.host)
    blocked = policy.hostname_blocked(folded)
    if blocked is not None:
        return deny({blocked})

    try:
        literal = _normalize_literal(folded, parsed.bracketed)
    except ValueError:
        return deny({"invalid_url"})

    if literal is not None:
        codes, is_public = _classify(literal, policy)
        if codes:
            return deny(set(codes))
        if not is_public:
            return deny({"not_lab_public"})
        return _Admission(True, set(), parsed, pinned_ip=str(literal))

    seq = state.lookup_seq.get(folded, 0) + 1
    try:
        addresses = resolver.resolve(folded)
    except LabNxDomain:
        return deny({"nxdomain"})
    state.lookup_seq[folded] = seq
    state.resolved.append({"host": folded, "addresses": list(addresses), "lookup_seq": seq})

    blocked_codes: set[str] = set()
    public: list[str] = []
    not_public = False
    for raw in addresses:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            not_public = True
            continue
        if isinstance(ip, ipaddress.IPv6Address):
            embedded = _extract_embedded_ipv4(ip)
            if embedded is not None:
                ip = embedded
        codes, is_public = _classify(ip, policy)
        if codes:
            blocked_codes |= codes
        elif is_public:
            public.append(str(ip))
        else:
            not_public = True

    if blocked_codes and public:
        return deny(set(blocked_codes) | {"mixed_blocked_records"})
    if blocked_codes:
        return deny(set(blocked_codes))
    if not_public or not public:
        return deny({"not_lab_public"})
    return _Admission(True, set(), parsed, pinned_ip=public[0])


def _base_report(url: str, parsed: _Parsed, state: _State) -> dict[str, Any]:
    return {
        "url": url,
        "decision": None,
        "reason_codes": [],
        "parsed": parsed.as_report(),
        "resolved": state.resolved,
        "pinned_ip": None,
        "redirect_chain": [],
        "fetch": None,
    }


def check_url(url: str, policy: Policy, resolver: LabResolver) -> dict[str, Any]:
    state = _State()
    admission = _admit(url, policy, resolver, state)
    report = _base_report(url, admission.parsed, state)
    if admission.allowed:
        report["decision"] = "allow"
        report["pinned_ip"] = admission.pinned_ip
    else:
        report["decision"] = "deny"
        report["reason_codes"] = sorted(admission.codes)
    return report


def fetch_url(
    url: str,
    policy: Policy,
    resolver: LabResolver,
    http: LabHttp,
    out_path: str | Path | None,
) -> dict[str, Any]:
    state = _State()
    out = Path(out_path) if out_path is not None else None
    report: dict[str, Any] | None = None
    current = url
    redirects_left = policy.max_redirects
    chain: list[dict[str, Any]] = []

    def deny(codes: set[str]) -> dict[str, Any]:
        assert report is not None
        report["decision"] = "deny"
        report["reason_codes"] = sorted(codes)
        if out is not None and out.exists():
            out.unlink()
        return report

    while True:
        admission = _admit(current, policy, resolver, state)
        if report is None:
            report = _base_report(url, admission.parsed, state)
            report["redirect_chain"] = chain
        if not admission.allowed:
            codes = set(admission.codes)
            if chain:
                codes.add("redirect_to_blocked")
                chain[-1]["decision"] = "deny"
            return deny(codes)

        report["pinned_ip"] = admission.pinned_ip
        try:
            resp = http.request(
                admission.pinned_ip,
                admission.parsed.port,
                method="GET",
                path=admission.parsed.path,
                headers={"Host": admission.parsed.host or ""},
            )
        except LabUnreachable:
            return deny({"unreachable"})

        location = resp.headers.get("Location")
        if resp.status in REDIRECT_STATUSES and location:
            target = urljoin(current, location)
            hop = {"from": current, "status": resp.status, "location": target, "decision": "allow"}
            chain.append(hop)
            if redirects_left <= 0:
                hop["decision"] = "deny"
                return deny({"too_many_redirects"})
            redirects_left -= 1
            current = target
            continue

        body = resp.body
        if out is not None:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(body)
        report["decision"] = "allow"
        report["fetch"] = {
            "status": resp.status,
            "bytes": len(body),
            "path": str(out) if out is not None else None,
        }
        return report
