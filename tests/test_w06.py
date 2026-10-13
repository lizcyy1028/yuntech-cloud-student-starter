"""Offline W6 checks: consumer decisions, device filter, gateway batch and IoT policies. No AWS calls."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "deploy"), str(ROOT / "tools")]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


consumer = load("w06_consumer", "app/consumer.py")
gateway_sim = load("w06_gateway_sim", "tools/gateway_sim.py")
iot_up = load("w06_iot_up", "deploy/iot_up.py")
import test_events  # noqa: E402  (reuses the server fixture and tokens)

DEVICES = frozenset(f"g7-m03-d{number:02d}" for number in range(1, 11))


class ConsumerDecisions(unittest.TestCase):
    def decide(self, event, status=201):
        posted = []

        def post(body):
            posted.append(json.loads(body))
            return status

        payload = event if isinstance(event, bytes) else json.dumps(event).encode()
        return consumer.handle(payload, DEVICES, post), posted

    def event(self, **changes):
        return {"event_id": "g7-m03-r1-d01-01", "device_id": "g7-m03-d01",
                "observed_at": "2026-10-13T10:00:00+08:00", "type": "status"} | changes

    def test_api_status_becomes_a_result(self):
        for status, result in ((201, "created"), (200, "duplicate"), (400, "rejected"), (409, "rejected"),
                               (401, "rejected"), (503, "error"), (0, "error")):
            with self.subTest(status):
                outcome, posted = self.decide(self.event(), status)
                self.assertEqual(outcome, ("g7-m03-r1-d01-01", result))
                self.assertEqual(posted, [self.event()])

    def test_device_not_on_the_list_is_rejected_without_calling_the_api(self):
        for device_id in ("g7-m03-d99", "g8-m01-d01", "", None, ["g7-m03-d01"], 7):
            with self.subTest(device_id):
                outcome, posted = self.decide(self.event(device_id=device_id))
                self.assertEqual(outcome, ("g7-m03-r1-d01-01", "rejected"))
                self.assertEqual(posted, [])

    def test_malformed_messages_are_rejected_and_cannot_forge_log_lines(self):
        for payload in (b"not json", b"\xff\xfe", b"[1, 2]", b'"text"'):
            self.assertEqual(self.decide(payload), (("invalid", "rejected"), []))
        forged = self.event(event_id="x result=created\nevent_id=y")
        self.assertEqual(self.decide(forged, 400)[0], ("invalid", "rejected"))


class GatewayBatch(unittest.TestCase):
    def test_batch_is_30_events_one_resend_and_one_unlisted_device(self):
        prefix, payloads = gateway_sim.build_messages("g7-m03", "r1")
        events = [json.loads(payload) for payload in payloads]
        self.assertEqual((prefix, len(events)), ("g7-m03-r1", 32))
        self.assertEqual(len({item["event_id"] for item in events[:30]}), 30)
        self.assertEqual({item["device_id"] for item in events[:30]}, DEVICES)
        self.assertEqual(events[0]["event_id"], "g7-m03-r1-d01-01")
        self.assertEqual(payloads[30], payloads[0])
        self.assertEqual((events[31]["event_id"], events[31]["device_id"]), ("g7-m03-r1-d99-01", "g7-m03-d99"))
        self.assertEqual(sum(item["device_id"] == "g7-m03-d01" for item in events[:30]), 3)

    def test_prefix_is_validated(self):
        for run in ("r 1", "r1'; --", "r" * 40):
            with self.assertRaises(gateway_sim.labctl.LabError):
                gateway_sim.build_messages("g7-m03", run)


class DeviceFilter(test_events.ServerCase):
    def test_gateway_events_pass_the_api_contract_and_filter_by_device(self):
        _, payloads = gateway_sim.build_messages("g7-m03", "r1")
        statuses = [self.call("POST", "/events", test_events.REPORTER, payload.encode())[0]
                    for payload in payloads]
        # The d99 event is valid for the API on its own; only the consumer's list stops it.
        self.assertEqual(statuses, [201] * 30 + [200, 201])
        status, body = self.call("GET", "/events?device_id=g7-m03-d01", test_events.OPERATOR)
        self.assertEqual(status, 200)
        self.assertEqual(sorted(item["event_id"] for item in body["events"]),
                         ["g7-m03-r1-d01-01", "g7-m03-r1-d01-02", "g7-m03-r1-d01-03"])
        received = [item["received_at"] for item in body["events"]]
        self.assertEqual(received, sorted(received, reverse=True))
        self.assertEqual(self.call("GET", "/events?device_id=g7-m03-d50", test_events.OPERATOR)[1]["events"], [])
        self.assertEqual(len(self.call("GET", "/events", test_events.OPERATOR)[1]["events"]), 31)

    def test_filter_needs_the_operator_and_a_well_formed_device_id(self):
        self.assertEqual(self.call("GET", "/events?device_id=g7-m03-d01", test_events.REPORTER)[0], 403)
        self.assertEqual(self.call("GET", "/events?device_id=g7-m03-d01", None)[0], 401)
        status, body = self.call("GET", "/events?device_id=bad%20id%27", test_events.OPERATOR)
        self.assertEqual((status, body["field"]), (400, "device_id"))

    def test_display_page_has_the_device_input(self):
        page = self.call("GET", "/")[1]
        for expected in ('id="device-id"', "encodeURIComponent", "textContent"):
            self.assertIn(expected, page)


class IotPoliciesAndTls(unittest.TestCase):
    def test_policies_use_exact_resources(self):
        documents = {role: iot_up.policy_document(role, "g7-m03", "123456789012", "us-east-1")
                     for role in iot_up.ROLES}
        self.assertNotIn("*", json.dumps(documents))
        base = "arn:aws:iot:us-east-1:123456789012:"
        granted = {role: {(item["Action"], item["Resource"]) for item in document["Statement"]}
                   for role, document in documents.items()}
        self.assertEqual(granted["gw"], {("iot:Connect", base + "client/gw-g7-m03"),
                                         ("iot:Publish", base + "topic/cxe/g7-m03/gw/events")})
        self.assertEqual(granted["consumer"], {
            ("iot:Connect", base + "client/consumer-g7-m03"),
            ("iot:Subscribe", base + "topicfilter/cxe/g7-m03/gw/events"),
            ("iot:Receive", base + "topic/cxe/g7-m03/gw/events")})

    def test_tls_verification_is_never_switched_off(self):
        # Joined at run time so neither this file nor its bytecode cache matches the course's
        # own grep for these names.
        forbidden = ["_".join(parts) for parts in (("tls", "insecure", "set"), ("CERT", "NONE"))]
        for folder in ("app", "tools", "tests", "deploy"):
            for path in (ROOT / folder).glob("*.py"):
                text = path.read_text(encoding="utf-8")
                for name in forbidden:
                    self.assertNotIn(name, text, f"{name} in {path.name}")
