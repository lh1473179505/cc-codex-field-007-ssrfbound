"""Self-check harness for ssrfbound check/fetch against the lab fixtures."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).parent
POLICY = ROOT / "fixtures" / "policy.json"
DNS = ROOT / "fixtures" / "lab_dns.json"
HTTP = ROOT / "fixtures" / "lab_http.json"

failures = []


def run(cmd, url, out, report):
    argv = [sys.executable, "-m", "ssrfbound", cmd, "--url", url,
            "--policy", str(POLICY), "--dns", str(DNS), "--report", str(report)]
    if cmd == "fetch":
        argv += ["--http", str(HTTP), "--out", str(out)]
    proc = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True)
    rep = json.loads(report.read_text(encoding="utf-8")) if report.exists() else None
    return proc, rep


def expect_check(url, decision, codes=None):
    with tempfile.TemporaryDirectory() as td:
        proc, rep = run("check", url, Path(td) / "out", Path(td) / "r.json")
        want_rc = 0 if decision == "allow" else 1
        note = ""
        ok = proc.returncode == want_rc and rep and rep["decision"] == decision
        if ok and rep["fetch"] is not None:
            ok, note = False, "check fetch field must be null"
        if ok and codes:
            missing = [c for c in codes if c not in rep["reason_codes"]]
            if missing:
                ok, note = False, "missing codes %s in %s" % (missing, rep["reason_codes"])
        if not ok:
            failures.append("check %s: rc=%s rep=%s %s" % (url, proc.returncode, rep, note))


def expect_fetch(url, decision, body=None, codes=None, pinned=None, lookups=None):
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "body"
        proc, rep = run("fetch", url, out, Path(td) / "r.json")
        want_rc = 0 if decision == "allow" else 1
        note = ""
        ok = proc.returncode == want_rc and rep and rep["decision"] == decision
        if ok and decision == "allow":
            if body is not None and (not out.exists() or out.read_bytes().decode() != body):
                ok, note = False, "body mismatch: %r" % (out.read_bytes() if out.exists() else None,)
            elif out.exists() and (rep["fetch"] is None or rep["fetch"]["bytes"] != len(out.read_bytes())):
                ok, note = False, "bad fetch field %s" % (rep["fetch"],)
        if ok and decision == "deny":
            if out.exists():
                ok, note = False, "out file leaked on deny"
            if rep["fetch"] is not None:
                ok, note = False, "fetch field must be null on deny"
        if ok and codes:
            missing = [c for c in codes if c not in rep["reason_codes"]]
            if missing:
                ok, note = False, "missing codes %s in %s" % (missing, rep["reason_codes"])
        if ok and pinned is not None and rep["pinned_ip"] != pinned:
            ok, note = False, "pinned_ip=%s want %s" % (rep["pinned_ip"], pinned)
        if ok and lookups is not None:
            got = sum(1 for r in rep["resolved"] if r["host"] == "rebind.lab")
            if got != lookups:
                ok, note = False, "lookups=%s want %s: %s" % (got, lookups, rep["resolved"])
        if not ok:
            failures.append("fetch %s: rc=%s rep=%s %s" % (url, proc.returncode, rep, note))


for u in ("file:///etc/passwd", "gopher://public.lab/", "dict://public.lab/"):
    expect_check(u, "deny", ["blocked_scheme"])
expect_check("http://public.lab:22/", "deny", ["blocked_port"])
expect_check("http://localhost/", "deny", ["blocked_hostname"])
expect_check("http://metadata.google.internal/", "deny", ["blocked_hostname"])
for u in ("http://admin.internal/", "http://foo.localhost/", "http://app.corp/"):
    expect_check(u, "deny", ["blocked_suffix"])
for u in ("http://127.0.0.1/", "http://127.1/", "http://2130706433/",
          "http://0177.0.0.1/", "http://0x7f.0.0.1/", "http://0x7f000001/",
          "http://[::1]/", "http://[::ffff:127.0.0.1]/", "http://[::ffff:7f00:1]/",
          "http://[::7f00:1]/", "http://[64:ff9b::7f00:1]/", "http://[2002:7f00:1::]/"):
    expect_check(u, "deny", ["loopback"])
for u in ("http://10.1.2.3/", "http://192.168.1.8/", "http://172.16.0.9/",
          "http://intranet.lab/", "http://内网.lab/", "http://xn--v6q792i.lab/",
          "http://[fd12:3456:789a::1]/"):
    expect_check(u, "deny", ["private"])
expect_check("http://169.254.169.254/latest/meta-data/", "deny", ["metadata"])
expect_check("http://0.0.0.0/", "deny", ["unspecified"])
for u in ("http://255.255.255.255/", "http://224.0.0.1/"):
    expect_check(u, "deny", ["multicast_or_reserved"])
expect_check("http://split.lab/", "deny", ["mixed_blocked_records"])
expect_check("http://public.lab@127.0.0.1/", "deny", ["loopback"])
expect_check("http://8.8.8.8/", "deny", ["not_lab_public"])
expect_check("http://no-such.lab/", "deny", ["nxdomain"])

for u in ("http://public.lab/", "http://public.lab./", "http://Public.LAB/",
          "http://127.0.0.1@public.lab/", "https://public.lab/",
          "http://[2001:db8:1::10]/", "http://[::ffff:198.51.100.10]/",
          "http://[::ffff:c633:640a]/", "http://[2002:c633:640a::]/",
          "http://rebind.lab/"):
    expect_check(u, "allow")

expect_fetch("http://public.lab/", "allow", body="public-home", pinned="198.51.100.10")
expect_fetch("http://public.lab:8080/alt", "allow", body="alt-port")
expect_fetch("http://v6.lab/", "allow", body="v6-home", pinned="2001:db8:1::10")
expect_fetch("http://rebind.lab/", "allow", body="public-home", pinned="198.51.100.10", lookups=1)
expect_fetch("http://public.lab/hop1", "allow", body="ok-final")
expect_fetch("http://public.lab/chain1", "allow", body="too-deep")

expect_fetch("http://public.lab/deep1", "deny", codes=["too_many_redirects"])
expect_fetch("http://public.lab/loop", "deny", codes=["too_many_redirects"])
expect_fetch("http://public.lab/go", "deny", codes=["redirect_to_blocked", "loopback"])
expect_fetch("http://public.lab/to-meta", "deny", codes=["redirect_to_blocked", "metadata"])
expect_fetch("http://public.lab/to-intranet", "deny", codes=["redirect_to_blocked", "private"])

proc = subprocess.run([sys.executable, "-m", "ssrfbound", "dump-lab",
                       "--dns", str(DNS), "--http", str(HTTP)], cwd=ROOT,
                      capture_output=True, text=True)
if proc.returncode != 0:
    failures.append("dump-lab broke: " + proc.stderr)

proc = subprocess.run([sys.executable, "-m", "ssrfbound", "check", "--url", "http://public.lab/",
                       "--policy", "/nonexistent.json", "--dns", str(DNS),
                       "--report", "/tmp/ssrfbound-selfcheck-bad.json"], cwd=ROOT,
                      capture_output=True, text=True)
if proc.returncode != 2:
    failures.append("missing policy should exit 2, got %s" % proc.returncode)

if failures:
    print("FAIL (%d):" % len(failures))
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("all self-checks passed")
