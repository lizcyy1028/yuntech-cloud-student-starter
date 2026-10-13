#!/usr/bin/env python3
"""W6 reconciliation: PUBACKs, consumer results, database rows and the device filter for one run.

Prints a pasteable report. Tokens, passwords and private keys are never printed.
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

PREFIX_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,40}$")
RESULTS = ("created", "duplicate", "rejected", "error")
# Both run on the host as root. PREFIX is validated before it is placed here, and psql still
# receives it as a variable so it is never part of the SQL text.
COUNT_RESULTS = """journalctl -u inspection-consumer -o cat --no-pager \\
  | grep -F 'event_id=PREFIX-' | grep -o 'result=[a-z]*' | sort | uniq -c || true
"""
COUNT_ROWS = """set -euo pipefail
set -a; . /etc/inspection/app.env; set +a
PGPASSWORD="$DB_PASSWORD" psql "host=$DB_HOST dbname=$DB_NAME user=$DB_USER sslmode=verify-full sslrootcert=/etc/inspection/rds-ca.pem" -At -v prefix="PREFIX-" <<'SQL'
SELECT count(*) FROM events WHERE left(event_id, length(:'prefix')) = :'prefix';
SQL
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, help="Your code, e.g. g03-m2")
    parser.add_argument("--run", required=True, help="Run label used with gateway_sim.py, e.g. r1")
    args = parser.parse_args()
    prefix = f"{args.code}-{args.run}"
    if not PREFIX_PATTERN.fullmatch(prefix):
        raise labctl.LabError("The run prefix must match ^[A-Za-z0-9-]{1,40}$.")
    cfg = labctl.settings()
    labctl.verify(cfg)
    host = labctl.running_host(cfg, labctl.load_resources())["PublicIpAddress"]
    operator = labctl.read_env(labctl.LOCAL / "app.env")["OPERATOR_TOKEN"]

    last_run = json.loads((labctl.LOCAL / "w06-last-run.json").read_text(encoding="utf-8"))
    if last_run["prefix"] != prefix:
        raise labctl.LabError(f"The last gateway run used prefix {last_run['prefix']}, not {prefix}.")

    def on_host(script, label):
        return labctl.ssh_run(cfg, host, "sudo bash -s", stdin=script.replace("PREFIX", prefix).encode("utf-8"),
                              label=label)

    # QoS 1 delivery and the API calls take a moment: retry until all 32 are accounted for.
    deadline = time.monotonic() + 60
    while True:
        counts = dict.fromkeys(RESULTS, 0)
        for line in on_host(COUNT_RESULTS, "consumer log count").splitlines():
            number, _, name = line.strip().partition(" result=")
            if name in counts:
                counts[name] = int(number)
        if sum(counts.values()) >= last_run["sent"] or time.monotonic() > deadline:
            break
        time.sleep(5)
    rows = on_host(COUNT_ROWS, "psql count on the host").strip()

    device = f"{args.code}-d01"
    with labctl.http_base(cfg, host) as base:
        _, health = labctl.health(base)
        status, text = labctl.http("GET", f"{base}/events?device_id={device}", token=operator)
    filtered = ([item["event_id"] for item in json.loads(text)["events"] if item["event_id"].startswith(prefix + "-")]
                if status == 200 else [])

    print(f"host {host}  version {health.get('version')}  db_configured {health.get('db_configured')}")
    print(f"prefix {prefix}")
    print(f"gateway PUBACK: {last_run['puback_ok']}/{last_run['sent']}")
    print("consumer created/duplicate/rejected/error: " + "/".join(str(counts[name]) for name in RESULTS))
    print(f"database rows with this prefix: {rows}")
    print(f"GET /events?device_id={device} -> HTTP {status}; events with this prefix: {len(filtered)} "
          f"{sorted(filtered)}")
    expected = (last_run["puback_ok"] == 32 and [counts[name] for name in RESULTS] == [30, 1, 1, 0]
                and rows == "30" and len(filtered) == 3)
    print("matches the expected 32 / 30-1-1-0 / 30 / 3: " + ("yes" if expected else "NO"))
    return 0 if expected else 1


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
