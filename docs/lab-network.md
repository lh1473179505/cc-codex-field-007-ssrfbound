# Lab network

This repository does not use the real Internet. DNS and HTTP are provided by in-process fixtures.

## DNS (`fixtures/lab_dns.json`)

Load with `ssrfbound.lab_dns.LabResolver.from_file`. Call `resolve(name)` to get a list of address strings (A then AAAA, in file order).

Names are compared after trimming a trailing dot, folding case, and applying IDNA (so `内网.lab` and `xn--v6q792i.lab` are the same name).

Most names have a fixed record set. `rebind.lab` is different: it has a `sequence`. The first `resolve("rebind.lab")` returns `198.51.100.10`. The second and later calls return `127.0.0.1`. The sequence does not wrap back to the public address.

`split.lab` returns both `198.51.100.10` and `10.0.0.5` in a single lookup.

Unknown names raise `LabNxDomain`.

## HTTP (`fixtures/lab_http.json`)

Load with `ssrfbound.lab_http.LabHttp.from_file`. Call:

```python
resp = http.request(ip, port, method="GET", path="/", headers={"Host": "public.lab"})
# resp.status, resp.headers, resp.body
```

Routing is by destination IP, port, and path only. The Host header is not used to choose a server. There is no TLS and no real socket. A request to an IP:port that is not in the fixture raises `LabUnreachable`. A known server with an unknown path returns 404.

## Address plan

| Address | Role |
|---|---|
| `198.51.100.10` | Simulated public origin for `public.lab` |
| `198.51.100.11` | Simulated public origin for `images.lab` |
| `2001:db8:1::10` | Simulated public IPv6 for `v6.lab` |
| `10.1.2.3` | Intranet |
| `10.0.0.5` | Private address mixed into `split.lab` |
| `127.0.0.1` | Loopback |
| `169.254.169.254` | Link-local metadata |

`198.51.100.0/24` and `2001:db8:1::/64` are the only ranges treated as lab-public (see `lab_public_cidrs` in the policy). Other globally unroutable or special ranges are not automatically "public".

## Policy (`fixtures/policy.json`)

`ssrfbound.policy.load_policy` returns the lists and `max_redirects`. `Policy.hostname_blocked(host)` only checks the hostname / suffix lists. It does not parse IP literals and does not consult DNS.
