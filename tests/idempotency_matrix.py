#!/usr/bin/env python3
"""W5 idempotency matrix: runs the 5 rows against the deployed host and prints a pasteable report.

Tokens come from .local/app.env; the database password stays on the host. None are printed.
"""
import argparse
import json
from pathlib import Path
import re
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import labctl  # noqa: E402

FIXTURES = ROOT / "tests/fixtures"
# Runs on the host as root: the password goes from the secret file into the environment only.
COUNT_ON_HOST = """set -euo pipefail
set -a; . /etc/inspection/app.env; set +a
PGPASSWORD="$DB_PASSWORD" psql "host=$DB_HOST dbname=$DB_NAME user=$DB_USER sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem" -At -v event_id="EVENT_ID" <<'SQL'
SELECT count(*) FROM events WHERE event_id = :'event_id';
SQL
"""


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
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", event["event_id"]):
        raise labctl.LabError("event_id must be 1-64 characters of letters, digits, '-' or '_'.")
    original = json.dumps(event).encode("utf-8")
    changed = json.dumps(event | {"note": "same event_id, different note"}).encode("utf-8")
    mismatches = 0

    def report(number, label, expected, actual, text):
        nonlocal mismatches
        if reporter in text or operator in text:
            text = "<response withheld: it contained a token>"
        verdict = "ok" if actual == expected else f"MISMATCH (expected {expected})"
        mismatches += actual != expected
        print(f"#{number} {label}\n   {verdict}\n   {text}")

    with labctl.http_base(cfg, host) as base:
        status, health = labctl.health(base)
        print(f"host {host}  /health {status}  version {health.get('version')}  "
              f"db_configured {health.get('db_configured')}")

        status, text = labctl.http("POST", base + "/events", token=reporter, body=original)
        report(1, "send a new event", "HTTP 201", f"HTTP {status}", f"HTTP {status}  {text}")
        status, text = labctl.http("POST", base + "/events", token=reporter, body=original)
        report(2, "resend it unchanged", "HTTP 200", f"HTTP {status}", f"HTTP {status}  {text}")
        status, text = labctl.http("POST", base + "/events", token=reporter, body=changed)
        report(3, "same event_id, different note", "HTTP 409", f"HTTP {status}", f"HTTP {status}  {text}")

        labctl.ssh_run(cfg, host, "sudo systemctl restart inspection", label="inspection restart")
        restarted, _ = labctl.wait_for(lambda: labctl.health(base)[1].get("started_at"),
                                       "/health after the restart", 30, 1)
        status, text = labctl.http("GET", f"{base}/events/{event['event_id']}", token=operator)
        report(4, f"after 'sudo systemctl restart inspection' (started_at {health.get('started_at')} -> "
                  f"{restarted}), read row 1", "HTTP 200", f"HTTP {status}", f"HTTP {status}  {text}")

    count = labctl.ssh_run(cfg, host, "sudo bash -s",
                           stdin=COUNT_ON_HOST.replace("EVENT_ID", event["event_id"]).encode("utf-8"),
                           label="psql count on the host").strip()
    report(5, "psql on EC2: count of row 1's event_id", "1", count, f"count = {count}")
    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
