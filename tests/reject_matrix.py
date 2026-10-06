#!/usr/bin/env python3
"""W4 rejection matrix: runs the 7 rows against the deployed host and prints a pasteable report.

Tokens are read from .local/app.env and are never printed; neither are request headers.
"""
import argparse
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import labctl  # noqa: E402

FIXTURES = ROOT / "tests/fixtures"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-id", help="event_id for row 1 (default: <prefix>-<UTC time>)")
    args = parser.parse_args()
    cfg = labctl.settings()
    labctl.verify(cfg)
    # Look up the address now: it changes on every Start.
    host = labctl.running_host(cfg, labctl.load_resources())["PublicIpAddress"]
    tokens = labctl.read_env(labctl.LOCAL / "app.env")
    reporter, operator = tokens["REPORTER_TOKEN"], tokens["OPERATOR_TOKEN"]

    event = json.loads((FIXTURES / "event-valid.json").read_text(encoding="utf-8"))
    event["event_id"] = args.event_id or f"{labctl.prefix(cfg)}-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}"
    valid = json.dumps(event).encode("utf-8")
    no_timezone = (FIXTURES / "event-reject-no-timezone.json").read_bytes()

    with labctl.http_base(cfg, host) as base:
        status, health = labctl.health(base)
        print(f"host {host}  /health {status}  version {health.get('version')}  "
              f"auth_configured {health.get('auth_configured')}")
        rows = [
            (1, "reporter sends a valid event", 201, ("POST", "/events", reporter, valid)),
            (2, "same event, no token", 401, ("POST", "/events", None, valid)),
            (3, "operator token sends the event", 403, ("POST", "/events", operator, valid)),
            (4, "reporter, observed_at without timezone", 400, ("POST", "/events", reporter, no_timezone)),
            (5, "reporter sends row 1 again", 409, ("POST", "/events", reporter, valid)),
            (6, "reporter token reads the list", 403, ("GET", "/events", reporter, None)),
            (7, "operator token reads the list", 200, ("GET", "/events", operator, None)),
        ]
        mismatches = 0
        for number, label, expected, (method, path, token, body) in rows:
            status, text = labctl.http(method, base + path, token=token, body=body)
            if reporter in text or operator in text:
                text = "<response withheld: it contained a token>"
            if number == 7 and status == 200:
                listed = [item for item in json.loads(text)["events"] if item["event_id"] == event["event_id"]]
                text = json.dumps({"contains_row_1": bool(listed), "row_1": listed[:1]}, ensure_ascii=False)
            verdict = "ok" if status == expected else f"MISMATCH (expected {expected})"
            mismatches += status != expected
            print(f"#{number} {label}\n   HTTP {status}  {verdict}\n   {text}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
