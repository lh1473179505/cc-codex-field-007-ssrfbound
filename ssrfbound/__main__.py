"""CLI entry. check/fetch are the work to be implemented; dump-lab already works."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ssrfbound.lab_dns import LabResolver
from ssrfbound.lab_http import LabHttp
from ssrfbound.policy import load_policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ssrfbound")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp: argparse.ArgumentParser, *, need_http: bool) -> None:
        sp.add_argument("--url", required=True)
        sp.add_argument("--policy", required=True, help="path to policy JSON")
        sp.add_argument("--dns", required=True, help="path to lab DNS JSON")
        sp.add_argument("--report", required=True, help="path to write the JSON report")
        if need_http:
            sp.add_argument("--http", required=True, help="path to lab HTTP JSON")
            sp.add_argument("--out", required=True, help="path to write the response body on allow")

    add_common(sub.add_parser("check", help="admit or deny a URL without fetching"), need_http=False)
    add_common(sub.add_parser("fetch", help="admit, pin an IP, and fetch via the lab transport"), need_http=True)

    dump = sub.add_parser("dump-lab", help="print the lab DNS and HTTP topology")
    dump.add_argument("--dns", required=True)
    dump.add_argument("--http", required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)

    if args.cmd == "dump-lab":
        dns = json.loads(Path(args.dns).read_text(encoding="utf-8"))
        http = json.loads(Path(args.http).read_text(encoding="utf-8"))
        resolver = LabResolver.from_file(args.dns)
        # Show current first-lookup answers without consuming rebind sequences
        # by reading the file rather than calling resolve() here.
        print(json.dumps({"dns": dns, "http": http, "resolver_class": type(resolver).__name__}, ensure_ascii=False, indent=2))
        return 0

    try:
        policy = load_policy(args.policy)
        resolver = LabResolver.from_file(args.dns)
    except Exception as exc:
        print(f"failed to load policy or lab DNS: {exc}", file=sys.stderr)
        return 2

    if args.cmd == "check":
        from ssrfbound.engine import check_url

        try:
            report = check_url(args.url, policy, resolver)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return _write_report(args.report, report)

    if args.cmd == "fetch":
        from ssrfbound.engine import fetch_url

        try:
            http = LabHttp.from_file(args.http)
        except Exception as exc:
            print(f"failed to load lab HTTP: {exc}", file=sys.stderr)
            return 2
        try:
            report = fetch_url(args.url, policy, resolver, http, args.out)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        return _write_report(args.report, report)

    p.error("unknown command")
    return 2


def _write_report(path: str, report: dict) -> int:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    decision = str(report.get("decision", "")).lower()
    if decision == "allow":
        return 0
    if decision == "deny":
        return 1
    print("report is missing a decision of allow or deny", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
