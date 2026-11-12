# Report schema

Both `check` and `fetch` write a JSON object to `--report`. Required keys:

```json
{
  "url": "http://public.lab/",
  "decision": "allow",
  "reason_codes": [],
  "parsed": {
    "scheme": "http",
    "host": "public.lab",
    "port": 80,
    "userinfo": false
  },
  "resolved": [
    {"host": "public.lab", "addresses": ["198.51.100.10"], "lookup_seq": 1}
  ],
  "pinned_ip": "198.51.100.10",
  "redirect_chain": [],
  "fetch": null
}
```

- `decision` is exactly `"allow"` or `"deny"`.
- `reason_codes` is a list of string codes. On allow it may be empty. On deny it must contain the codes that caused the denial (order does not matter).
- `parsed.port` is the effective port after applying scheme defaults (http=80, https=443) or an explicit port.
- `parsed.userinfo` is true when the URL contained a userinfo component (`user@host` or `user:pass@host`).
- `resolved` lists DNS lookups that actually happened, in order. `lookup_seq` starts at 1 for that hostname in this process/resolver. IP literals must not be entered as DNS lookups.
- `pinned_ip` is the address chosen for a connection attempt, or `null` when nothing was pinned (for example a deny that happens before pinning).
- `redirect_chain` is a list of hops already followed:
  `{"from": "...", "status": 302, "location": "...", "decision": "allow"}`.
  The hop that gets denied should still be recorded, with `"decision": "deny"`.
- For `check`, `fetch` is always `null`.
- For `fetch` on allow, `fetch` is `{"status": 200, "bytes": 11, "path": "/tmp/out"}`.
  For `fetch` on deny, `fetch` is `null` and `--out` must not be written (or must be removed if a partial file was created).

Recognized reason codes:

| Code | When to use |
|---|---|
| `invalid_url` | Not a usable URL |
| `blocked_scheme` | Scheme is in the policy block list, or is not `http` / `https` |
| `blocked_port` | Effective port is not in `allowed_ports` |
| `blocked_hostname` | Hostname matches `blocked_hostnames` |
| `blocked_suffix` | Hostname matches `blocked_hostname_suffixes` |
| `loopback` | Address is loopback (after normalizing unusual literals / embeddings) |
| `private` | Address is RFC1918 or unique-local `fc00::/7` |
| `link_local` | Address is `169.254.0.0/16` or `fe80::/10` |
| `metadata` | Address is one of `metadata_ipv4`, or the hostname is a metadata name |
| `unspecified` | `0.0.0.0/8` or IPv6 `::` |
| `multicast_or_reserved` | Multicast / broadcast / other blocked CIDRs not covered above |
| `mixed_blocked_records` | A single lookup returned at least one blocked address together with a lab-public one |
| `nxdomain` | Lab resolver raised `LabNxDomain` |
| `redirect_to_blocked` | A redirect target failed admission |
| `too_many_redirects` | Following the next hop would exceed `max_redirects` |
| `not_lab_public` | A resolved or literal address is neither blocked-special nor in `lab_public_cidrs` (do not fetch the real Internet) |
