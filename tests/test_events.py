"""Offline W4/W5 event-contract checks driven by tests/fixtures; no AWS or database calls."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
SOURCE = (ROOT / "app/service.py").read_text(encoding="utf-8")
spec = importlib.util.spec_from_file_location("event_service", ROOT / "app/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)

REPORTER = "reporter-token-for-offline-tests"
OPERATOR = "operator-token-for-offline-tests"
TOKENS = {"REPORTER_TOKEN": REPORTER, "OPERATOR_TOKEN": OPERATOR}


def fixture(name):
    return (FIXTURES / name).read_bytes()


class ServerCase(unittest.TestCase):
    store_factory = staticmethod(service.MemoryStore)

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        version = Path(self.tempdir.name) / "version"
        version.write_text("b" * 40)
        self.server = service.make_server(version, port=0, store=self.store_factory(), environ=TOKENS)
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


class EventContract(ServerCase):
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

    def test_resend_is_idempotent_and_changed_content_conflicts(self):
        valid = fixture("event-valid.json")
        status, created = self.call("POST", "/events", REPORTER, valid)
        self.assertEqual(status, 201)
        # Same event_id and content: 200 with the stored event (original received_at), nothing added.
        self.assertEqual(self.call("POST", "/events", REPORTER, valid), (200, created))
        changed = json.dumps(json.loads(valid) | {"note": "a different note"}).encode()
        status, body = self.call("POST", "/events", REPORTER, changed)
        self.assertEqual((status, body["field"]), (409, "event_id"))
        without_note = json.loads(valid)
        del without_note["note"]
        self.assertEqual(self.call("POST", "/events", REPORTER, json.dumps(without_note).encode())[0], 409)
        self.assertEqual(self.call("GET", "/events", OPERATOR)[1]["events"], [created])

    def test_health_and_display_page(self):
        status, body = self.call("GET", "/health")
        self.assertEqual((status, body["auth_configured"], body["db_configured"]), (200, True, True))
        status, page = self.call("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("textContent", page)

    def test_source_keeps_secrets_and_events_out_of_unsafe_places(self):
        for forbidden in ("innerHTML", "localStorage", "sessionStorage", "?token=", "logging",
                          "execute(f", "sslmode=disable", '"disable"'):
            self.assertNotIn(forbidden, SOURCE)


class WithoutDatabase(ServerCase):
    store_factory = staticmethod(lambda: None)

    def test_service_starts_and_reports_db_not_configured(self):
        status, body = self.call("GET", "/health")
        self.assertEqual((status, body["db_configured"]), (200, False))
        # Identity is still checked first; only an authorized caller learns about the database.
        self.assertEqual(self.call("POST", "/events", None, fixture("event-valid.json"))[0], 401)
        status, body = self.call("POST", "/events", REPORTER, fixture("event-valid.json"))
        self.assertEqual((status, body), (503, {"error": "database_not_configured", "field": None}))
        self.assertEqual(self.call("GET", "/events", OPERATOR)[0], 503)


class FakePostgres:
    """Stands in for psycopg2: one table keyed by its first column, plus failure switches."""

    class Error(Exception):
        pass

    class OperationalError(Error):
        pass

    def __init__(self):
        self.rows = {}
        self.statements = []
        self.connect_arguments = None
        self.connect_error = None

    def connect(self, **arguments):
        self.connect_arguments = arguments
        if self.connect_error:
            raise self.OperationalError(self.connect_error)
        return FakeConnection(self)


class FakeConnection:
    def __init__(self, database):
        self.database = database
        self.rowcount = 0
        self.result = []

    def cursor(self):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def close(self):
        pass

    def execute(self, statement, parameters=()):
        self.database.statements.append((statement, parameters))
        rows = self.database.rows
        if statement.startswith("INSERT"):
            self.rowcount = 0 if parameters[0] in rows else 1
            rows.setdefault(parameters[0], tuple(parameters))
        elif "WHERE event_id" in statement:
            self.result = [rows[parameters[0]]] if parameters[0] in rows else []
        elif "WHERE device_id" in statement:
            matching = [row for row in reversed(list(rows.values())) if row[1] == parameters[0]]
            self.result = matching[:parameters[1]]
        elif statement.startswith("SELECT"):
            self.result = list(reversed(list(rows.values())))[:parameters[0]]

    def fetchone(self):
        return self.result[0] if self.result else None

    def fetchall(self):
        return self.result


class PostgresStoreLogic(unittest.TestCase):
    ENVIRON = {"DB_HOST": "db.example.internal", "DB_NAME": "inspection", "DB_USER": "inspection",
               "DB_PASSWORD": "not-a-real-password"}

    def setUp(self):
        self.database = FakePostgres()
        module = types.ModuleType("psycopg2")
        for name in ("connect", "Error", "OperationalError"):
            setattr(module, name, getattr(self.database, name))
        patcher = mock.patch.dict(sys.modules, {"psycopg2": module})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = service.PostgresStore(self.ENVIRON)

    def event(self, **changes):
        return {"event_id": "g7-m03-0001", "device_id": "g7-d01", "observed_at": "2026-10-06T10:00:00+08:00",
                "type": "status", "received_at": "2026-10-06T02:00:00Z"} | changes

    def test_primary_key_decides_created_same_or_conflict(self):
        first = self.event()
        self.assertEqual(self.store.add(first), ("created", first))
        resend = self.event(received_at="2026-10-06T02:05:00Z")
        self.assertEqual(self.store.add(resend), ("same", first))
        self.assertEqual(self.store.add(self.event(note="changed")), ("conflict", None))
        self.assertEqual(self.store.get("g7-m03-0001"), first)
        self.assertIsNone(self.store.get("missing"))
        self.assertEqual(self.store.latest(50), [first])
        self.assertEqual(len(self.database.rows), 1)

    def test_connection_verifies_tls_and_sql_is_parameterized(self):
        self.store.add(self.event(note="x'); DROP TABLE events; --"))
        arguments = self.database.connect_arguments
        self.assertEqual((arguments["sslmode"], arguments["sslrootcert"]),
                         ("verify-full", "/etc/inspection/rds-ca.pem"))
        for statement, parameters in self.database.statements:
            self.assertNotIn("DROP TABLE", statement)
            self.assertEqual(statement.count("%s"), len(parameters))

    def test_failures_expose_only_a_category(self):
        self.database.connect_error = ('connection to server at "db.example.internal", user "inspection" '
                                       'failed: FATAL: password authentication failed')
        with self.assertRaises(service.StoreError) as caught:
            self.store.latest(50)
        self.assertEqual(str(caught.exception), "authentication")
        self.assertIsNone(caught.exception.__cause__)
