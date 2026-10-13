#!/usr/bin/env python3
"""W6 consumer: MQTT 5 subscriber that forwards allowed device events to the local event API."""
import json
import os
import re
import urllib.error
import urllib.request

API_URL = "http://127.0.0.1:8080/events"
ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
SETTINGS = ("IOT_ENDPOINT", "IOT_TOPIC", "IOT_CLIENT_ID", "IOT_DEVICE_IDS", "IOT_CA", "IOT_CERT", "IOT_KEY",
            "REPORTER_TOKEN")


def classify(status):
    if status == 201:
        return "created"
    if status == 200:  # W5 idempotency: same event_id with the same content
        return "duplicate"
    return "rejected" if 400 <= status < 500 else "error"


def post_event(body, token):
    """POST one event to the local API; returns the HTTP status, or 0 when it cannot be reached."""
    request = urllib.request.Request(API_URL, data=body, method="POST", headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except (urllib.error.URLError, OSError):
        return 0


def handle(payload, device_ids, post):
    """Decide one message. Returns (event_id safe to log, result)."""
    try:
        event = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "invalid", "rejected"
    if not isinstance(event, dict):
        return "invalid", "rejected"
    event_id = event.get("event_id")
    # Only a well-formed event_id reaches the log line; anything else could forge log entries.
    logged_id = event_id if isinstance(event_id, str) and ID_PATTERN.fullmatch(event_id) else "invalid"
    # device_id is only a claim inside the message: the gateway certificate does not prove it,
    # so it must be on this consumer's own list before anything is sent to the API.
    device_id = event.get("device_id")
    if not isinstance(device_id, str) or device_id not in device_ids:
        return logged_id, "rejected"
    return logged_id, classify(post(json.dumps(event).encode("utf-8")))


def main():
    import paho.mqtt.client as mqtt  # installed on the host by the packer (2.1.0)
    config = {name: os.environ.get(name, "") for name in SETTINGS}
    missing = [name for name, value in config.items() if not value]
    if missing:
        raise SystemExit("missing settings: " + ", ".join(missing))
    device_ids = frozenset(item.strip() for item in config["IOT_DEVICE_IDS"].split(",") if item.strip())

    def on_connect(client, userdata, flags, reason_code, properties):
        if reason_code.value < 128:
            client.subscribe(config["IOT_TOPIC"], qos=1)  # again after every reconnect
        else:
            print(f"connect rc={reason_code.value}", flush=True)

    def on_subscribe(client, userdata, mid, reason_codes, properties):
        print(f"subscribed rc={reason_codes[0].value}", flush=True)

    def on_message(client, userdata, message):
        event_id, result = handle(message.payload, device_ids,
                                  lambda body: post_event(body, config["REPORTER_TOKEN"]))
        print(f"event_id={event_id} result={result}", flush=True)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=config["IOT_CLIENT_ID"],
                         protocol=mqtt.MQTTv5)
    # Mutual TLS: the broker's certificate and host name are verified against the Root CA.
    client.tls_set(ca_certs=config["IOT_CA"], certfile=config["IOT_CERT"], keyfile=config["IOT_KEY"])
    client.on_connect, client.on_subscribe, client.on_message = on_connect, on_subscribe, on_message
    client.connect(config["IOT_ENDPOINT"], 8883, keepalive=60)
    client.loop_forever()


if __name__ == "__main__":
    main()
