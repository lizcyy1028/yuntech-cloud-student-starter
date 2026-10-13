#!/usr/bin/env python3
"""W6 simulated gateway: one gateway identity reports for 10 device numbers (32 messages per run)."""
import argparse
from datetime import datetime
import json
import re

import iot_client
from iot_client import labctl

PREFIX_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,40}$")
LAST_RUN = labctl.LOCAL / "w06-last-run.json"


def build_messages(code, run):
    """30 events (10 devices x 3), then the first one again unchanged, then one from device d99."""
    prefix = f"{code}-{run}"
    if not PREFIX_PATTERN.fullmatch(prefix):
        raise labctl.LabError("The run prefix must match ^[A-Za-z0-9-]{1,40}$.")

    def event(device, sequence):
        return {"event_id": f"{prefix}-d{device:02d}-{sequence:02d}", "device_id": f"{code}-d{device:02d}",
                "observed_at": datetime.now().astimezone().isoformat(timespec="seconds"), "type": "status"}

    events = [event(device, sequence) for device in range(1, 11) for sequence in range(1, 4)]
    events.append(events[0])    # resent unchanged: the API answers 200 and adds nothing
    events.append(event(99, 1))  # a device number that is not on the consumer's list
    return prefix, [json.dumps(item, separators=(",", ":")) for item in events]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", required=True, help="Your code, e.g. g03-m2")
    parser.add_argument("--run", required=True, help="Run label, e.g. r1; use a new one for every run")
    args = parser.parse_args()
    labctl.settings()
    prefix, messages = build_messages(args.code, args.run)
    session = iot_client.Session("gw", args.code)
    connack = session.connect()
    print(f"connack={'none' if connack is None else connack}", flush=True)
    if connack is None or connack >= 128:
        return 1
    acknowledged = 0
    try:
        for payload in messages:
            # The next message is sent only after this one's PUBACK (matched by message id) arrived.
            puback = session.publish(iot_client.topic(args.code), payload)
            acknowledged += puback is not None and puback < 128
    finally:
        session.close()
    print(f"puback_ok={acknowledged}/{len(messages)}")
    LAST_RUN.write_text(json.dumps({"prefix": prefix, "puback_ok": acknowledged, "sent": len(messages),
                                    "finished": labctl.utc_now()}) + "\n", encoding="utf-8", newline="\n")
    return 0 if acknowledged == len(messages) else 1


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
