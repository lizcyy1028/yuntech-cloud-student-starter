"""Offline W4 event-contract checks driven by tests/fixtures; no AWS calls."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
SOURCE = (ROOT / "app/service.py").read_text(encoding="utf-8")
spec = importlib.util.spec_from_file_location("w04_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)

REPORTER = "reporter-token-for-offline-tests"
OPERATOR = "operator-token-for-offline-tests"


def fixture(name):
    return (FIXTURES / name).read_bytes()


class EventContract(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        version = Path(self.tempdir.name) / "version"
        version.write_text("b" * 40)
        with mock.patch.dict(os.environ, {"REPORTER_TOKEN": REPORTER, "OPERATOR_TOKEN": OPERATOR}):
            self.server = service.make_server(version, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.tempdir.cleanup()

    def call(self, method, path, token=None, body=None, content_type="application/json"):
        request = urllib.request.Request(self.base + path, data=body, method=method)
        if token:
            request.add_header("Authorization", "Bearer " + token)
        if body is not None:
            request.add_header("Content-Type", content_type)
        try:
            with urllib.request.urlopen(request) as response:
                status, text = response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            status, text = error.code, error.read().decode("utf-8")
        self.assertNotIn(REPORTER, text)
        self.assertNotIn(OPERATOR, text)
        return status, json.loads(text) if path != "/" else text

    def test_valid_fixture_is_created_listed_and_fetched(self):
        sent = json.loads(fixture("event-valid.json"))
        status, created = self.call("POST", "/events", REPORTER, fixture("event-valid.json"))
        self.assertEqual(status, 201)
        self.assertTrue(created["received_at"].endswith("Z"))
        self.assertEqual({key: created[key] for key in sent}, sent)
        status, listing = self.call("GET", "/events", OPERATOR)
        self.assertEqual((status, listing["events"]), (200, [created]))
        self.assertEqual(self.call("GET", "/events/" + sent["event_id"], OPERATOR), (200, created))
        self.assertEqual(self.call("GET", "/events/missing-id", OPERATOR)[0], 404)

    def test_reject_fixtures_name_the_field(self):
        for name, field in (("event-reject-no-timezone.json", "observed_at"),
                            ("event-reject-extra-field.json", "severity")):
            with self.subTest(name):
                status, body = self.call("POST", "/events", REPORTER, fixture(name))
                self.assertEqual(status, 400)
                self.assertEqual(set(body), {"error", "field"})
                self.assertEqual(body["field"], field)
        self.assertEqual(self.call("GET", "/events", OPERATOR)[1]["events"], [])

    def test_identity_is_checked_before_content(self):
        bad = fixture("event-reject-no-timezone.json")
        self.assertEqual(self.call("POST", "/events", None, bad)[0], 401)
        self.assertEqual(self.call("POST", "/events", "wrong-token", bad)[0], 401)
        self.assertEqual(self.call("POST", "/events", OPERATOR, bad)[0], 403)
        self.assertEqual(self.call("GET", "/events", REPORTER)[0], 403)
        self.assertEqual(self.call("GET", "/events", None)[0], 401)

    def test_other_body_rules(self):
        valid = fixture("event-valid.json")
        self.assertEqual(self.call("POST", "/events", REPORTER, valid, "text/plain")[0], 400)
        self.assertEqual(self.call("POST", "/events", REPORTER, b"{not json")[0], 400)
        oversized = json.dumps({"event_id": "g7-m03-0009", "note": "x" * 5000}).encode()
        self.assertEqual(self.call("POST", "/events", REPORTER, oversized)[0], 400)
        null_note = json.loads(valid) | {"note": None}
        status, body = self.call("POST", "/events", REPORTER, json.dumps(null_note).encode())
        self.assertEqual((status, body["field"]), (400, "note"))

    def test_duplicate_event_id_conflicts(self):
        valid = fixture("event-valid.json")
        self.assertEqual(self.call("POST", "/events", REPORTER, valid)[0], 201)
        status, body = self.call("POST", "/events", REPORTER, valid)
        self.assertEqual((status, body["field"]), (409, "event_id"))

    def test_health_and_display_page(self):
        status, body = self.call("GET", "/health")
        self.assertEqual((status, body["auth_configured"]), (200, True))
        status, page = self.call("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("textContent", page)

    def test_source_keeps_tokens_and_events_out_of_unsafe_places(self):
        for forbidden in ("innerHTML", "localStorage", "sessionStorage", "?token=", "logging"):
            self.assertNotIn(forbidden, SOURCE)
