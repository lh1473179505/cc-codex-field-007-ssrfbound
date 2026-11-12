# ssrfbound

A small SSRF admission layer and fetch helper that talks only to the in-process lab network in this repository. The policy, DNS fixture, and HTTP fixture already work. The `check` and `fetch` commands are stubs in this snapshot.

## Requirements

- Python 3.11+ (stdlib plus the `idna` package already used by the lab resolver)
- No containers. Do not add Docker files. Do not use the real network to resolve or fetch.

## Already working

```bash
python -m ssrfbound dump-lab --dns fixtures/lab_dns.json --http fixtures/lab_http.json
```

See `docs/lab-network.md` for the address plan and how `LabResolver` / `LabHttp` behave, and `docs/report-schema.md` for the report object.

## Intended CLI

```bash
python -m ssrfbound check \
  --url 'http://public.lab/' \
  --policy fixtures/policy.json \
  --dns fixtures/lab_dns.json \
  --report /tmp/ssrfbound-check.json

python -m ssrfbound fetch \
  --url 'http://public.lab/' \
  --policy fixtures/policy.json \
  --dns fixtures/lab_dns.json \
  --http fixtures/lab_http.json \
  --out /tmp/ssrfbound-body \
  --report /tmp/ssrfbound-fetch.json
```

Parameter names are fixed in `ssrfbound/__main__.py`. Keep them.

## Layout

- `ssrfbound/policy.py` — policy loader and hostname/suffix helper
- `ssrfbound/lab_dns.py` — deterministic lab DNS, including rebind sequences
- `ssrfbound/lab_http.py` — IP-based fixture HTTP
- `ssrfbound/engine.py` — `check_url` / `fetch_url` (not implemented yet)
- `fixtures/` — policy, DNS, and HTTP data
- `docs/` — lab and report notes
