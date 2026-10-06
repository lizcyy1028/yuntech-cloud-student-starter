#!/usr/bin/env python3
"""W5 T1: send one event, restart the service, and compare the event count before and after.

Run it against the W4 (in-memory) version to see the loss, and again after W5 to see it kept.
Tokens come from .local/app.env and are never printed.
"""
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import labctl  # noqa: E402


def main():
    cfg = labctl.settings()
    labctl.verify(cfg)
    host = labctl.running_host(cfg, labctl.load_resources())["PublicIpAddress"]
    tokens = labctl.read_env(labctl.LOCAL / "app.env")
    event = json.loads((ROOT / "tests/fixtures/event-valid.json").read_text(encoding="utf-8"))
    event["event_id"] = f"{labctl.prefix(cfg)}-t1-{time.strftime('%Y%m%d%H%M%S', time.gmtime())}"

    def listed(base):
        status, text = labctl.http("GET", base + "/events", token=tokens["OPERATOR_TOKEN"])
        if status != 200:
            return f"HTTP {status}"
        ids = [item["event_id"] for item in json.loads(text)["events"]]
        return f"{len(ids)} event(s); contains {event['event_id']}: {event['event_id'] in ids}"

    with labctl.http_base(cfg, host) as base:
        _, health = labctl.health(base)
        print(f"host {host}  version {health.get('version')}  db_configured {health.get('db_configured')}")
        status, _ = labctl.http("POST", base + "/events", token=tokens["REPORTER_TOKEN"],
                                body=json.dumps(event).encode("utf-8"))
        print(f"sent {event['event_id']}: HTTP {status}")
        print(f"before restart: {listed(base)}")
        labctl.ssh_run(cfg, host, "sudo systemctl restart inspection", label="inspection restart")
        labctl.wait_for(lambda: labctl.health(base)[0] == 200, "/health after the restart", 30, 1)
        print(f"after restart:  {listed(base)}")


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
