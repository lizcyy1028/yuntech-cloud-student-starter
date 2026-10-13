#!/usr/bin/env python3
"""W6 connection check: connect as the gateway or the consumer, then publish or subscribe once.

Prints MQTT 5 reason codes: below 128 is success, 135 is not authorized.
"""
import argparse
import json
import time

import iot_client
from iot_client import labctl


def shown(code):
    return "none" if code is None else code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--as", dest="role", choices=("gw", "consumer"), required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--pub", metavar="TOPIC")
    action.add_argument("--sub", metavar="TOPIC_FILTER")
    parser.add_argument("--wait", type=float, default=10, help="Seconds to keep listening after subscribing")
    args = parser.parse_args()
    code = labctl.prefix(labctl.settings())
    session = iot_client.Session(args.role, code)
    connack = session.connect()
    print(f"connack={shown(connack)}", flush=True)
    if connack is None or connack >= 128:
        return 1
    try:
        if args.pub:
            puback = session.publish(args.pub, json.dumps({"check": "t2", "code": code}, separators=(",", ":")))
            print(f"puback={shown(puback)}", flush=True)
            return 0 if puback is not None and puback < 128 else 1
        suback = session.subscribe(args.sub)
        print(f"suback={shown(suback)}", flush=True)
        if suback is None or suback >= 128:
            return 1
        deadline = time.monotonic() + args.wait
        while (remaining := deadline - time.monotonic()) > 0:
            message = session.wait("recv", remaining)
            if message:
                print(f"recv topic={message[1]} payload={message[2]}", flush=True)
        return 0
    finally:
        session.close()


if __name__ == "__main__":
    raise SystemExit(labctl.run(main))
