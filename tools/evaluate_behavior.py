"""Operator CLI for immutable Phase3A corpus/replay APIs (standard library only).

Write payloads are JSON files. Key comes from EDGEGUARD_OPERATION_KEY, never argv.
IDs are caller-supplied UUIDs: retry with the same ID after an ambiguous response.
"""

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import UUID


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8099")
    parser.add_argument("--output", type=Path)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("status")
    listing = sub.add_parser("datasets")
    listing.add_argument("--page", type=int, default=1)
    for command in (
        "create",
        "show",
        "label",
        "manifest",
        "readiness",
        "replay",
        "run",
    ):
        entry = sub.add_parser(command)
        entry.add_argument("id", type=UUID)
        if command in ("create", "label", "manifest"):
            entry.add_argument("payload", type=Path)
        if command == "replay":
            entry.add_argument("run_id", type=UUID)
    args = parser.parse_args()
    method, data = "GET", None
    if args.action in ("status", "datasets"):
        path = args.action + (f"?page={args.page}" if args.action == "datasets" else "")
    elif args.action == "run":
        path = f"runs/{args.id}"
    else:
        path = f"datasets/{args.id}"
        if args.action in ("create", "label", "manifest"):
            data = json.dumps(
                json.loads(args.payload.read_text(encoding="utf-8-sig"))
            ).encode()
            method = "PUT" if args.action == "create" else "POST"
            if args.action == "label":
                path += "/labels"
            elif args.action == "manifest":
                path += "/label-manifest"
        elif args.action == "readiness":
            path += "/readiness"
        elif args.action == "replay":
            path += f"/runs/{args.run_id}"
            method, data = "POST", b""
    headers = {"Content-Type": "application/json"}
    if method != "GET" and os.getenv("EDGEGUARD_OPERATION_KEY"):
        headers["X-Operation-Key"] = os.environ["EDGEGUARD_OPERATION_KEY"]
    request = Request(
        args.base_url.rstrip("/") + "/api/v1/evaluation/" + path,
        data=data,
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=60) as response:
            result = json.loads(response.read())
    except HTTPError as exc:
        print(
            f"HTTP {exc.code}: {exc.read().decode('utf-8', errors='replace')}",
            file=sys.stderr,
        )
        return 1
    except URLError as exc:
        print(f"Request failed: {exc.reason}", file=sys.stderr)
        return 1
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
        print(f"Saved {args.output.resolve()}")
    else:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
