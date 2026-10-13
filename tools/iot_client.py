#!/usr/bin/env python3
"""Shared MQTT 5 client for the W6 tools: mutual TLS on 8883 with files from .local/iot/."""
from pathlib import Path
import queue
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import labctl  # noqa: E402

IOT_DIR = Path(".local/iot")  # relative: labctl.settings() changes into the repo root
PORT = 8883


def topic(code):
    return f"cxe/{code}/gw/events"


class Session:
    """One connection as 'gw' or 'consumer'; replies arrive on self.events as (kind, ...) tuples."""

    def __init__(self, role, code):
        import paho.mqtt.client as mqtt  # pinned to 2.1.0 for MQTT 5 reason codes
        for name in ("endpoint", "AmazonRootCA1.pem", f"{role}.cert.pem", f"{role}.private.key"):
            if not (IOT_DIR / name).is_file():
                raise labctl.LabError(f"Missing .local/iot/{name}; run deploy/iot-up.sh first.")
        self.endpoint = (IOT_DIR / "endpoint").read_text(encoding="utf-8").strip()
        self.events = queue.Queue()
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=f"{role}-{code}",
                                  protocol=mqtt.MQTTv5)
        # Server certificate and host name are verified against Amazon Root CA 1 (the default).
        self.client.tls_set(ca_certs=str(IOT_DIR / "AmazonRootCA1.pem"),
                            certfile=str(IOT_DIR / f"{role}.cert.pem"),
                            keyfile=str(IOT_DIR / f"{role}.private.key"))
        self.client.on_connect = lambda c, u, flags, reason, props: self.events.put(("connack", reason.value))
        self.client.on_publish = lambda c, u, mid, reason, props: self.events.put(("puback", mid, reason.value))
        self.client.on_subscribe = lambda c, u, mid, reasons, props: self.events.put(
            ("suback", mid, reasons[0].value))
        self.client.on_message = lambda c, u, message: self.events.put(
            ("recv", message.topic, message.payload.decode("utf-8", "replace")))

    def wait(self, kind, timeout, mid=None):
        """Next reply of this kind (and message id); None when it does not arrive in time."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                event = self.events.get(timeout=remaining)
            except queue.Empty:
                return None
            if event[0] == kind and (mid is None or event[1] == mid):
                return event

    def connect(self, timeout=15):
        """Returns the CONNACK reason code, or None when the broker closed without one."""
        try:
            self.client.connect(self.endpoint, PORT, keepalive=30)
        except OSError:
            return None
        self.client.loop_start()
        reply = self.wait("connack", timeout)
        return reply[1] if reply else None

    def publish(self, topic_name, payload, timeout=10):
        """Publish with QoS 1 and wait for the PUBACK that carries the same message id."""
        info = self.client.publish(topic_name, payload, qos=1)
        reply = self.wait("puback", timeout, mid=info.mid)
        return reply[2] if reply else None

    def subscribe(self, topic_filter, timeout=10):
        _, mid = self.client.subscribe(topic_filter, qos=1)
        reply = self.wait("suback", timeout, mid=mid)
        return reply[2] if reply else None

    def close(self):
        self.client.disconnect()
        self.client.loop_stop()
