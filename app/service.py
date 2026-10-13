#!/usr/bin/env python3
"""Inspection event API: the W4 contract, stored in PostgreSQL with idempotent POST (W5)."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import sys
import threading
from urllib.parse import parse_qs, unquote, urlsplit


MAX_BODY_BYTES = 4 * 1024
EVENT_FIELDS = {"event_id", "device_id", "observed_at", "type", "note"}
ID_PATTERN = re.compile(r"[A-Za-z0-9_-]+\Z")
EVENT_TYPES = {"status", "anomaly", "test"}
EVENT_COLUMNS = ("event_id", "device_id", "observed_at", "type", "note", "received_at")
DB_SETTINGS = ("DB_HOST", "DB_NAME", "DB_USER", "DB_PASSWORD")
RDS_CA_FILE = "/etc/inspection/rds-ca.pem"

INDEX_HTML = r"""<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>&#24033;&#27298;&#20107;&#20214;</title>
</head>
<body>
  <main>
        <h1>&#24033;&#27298;&#20107;&#20214;</h1>
        <label for="operator-token">Operator &#27402;&#26454;</label>
    <input id="operator-token" type="password" autocomplete="off">
        <button id="clear-token" type="button">&#28165;&#31354;&#27402;&#26454;</button>
        <label for="device-id">&#35373;&#20633;&#32232;&#34399;</label>
    <input id="device-id" type="text" autocomplete="off" maxlength="32">
        <button id="load-events" type="button">&#35712;&#21462;&#20107;&#20214;</button>
    <p id="status" role="status" aria-live="polite"></p>
    <ol id="events"></ol>
  </main>
  <script>
    const tokenInput = document.querySelector("#operator-token");
    const deviceInput = document.querySelector("#device-id");
    const status = document.querySelector("#status");
    const eventList = document.querySelector("#events");

    // Empties only the token box; the events already shown stay on the page.
    document.querySelector("#clear-token").addEventListener("click", () => {
      tokenInput.value = "";
    });

    document.querySelector("#load-events").addEventListener("click", async () => {
    status.textContent = "\u8f09\u5165\u4e2d\u2026";
      eventList.replaceChildren();
      try {
        const deviceId = deviceInput.value.trim();
        const url = deviceId ? `/events?device_id=${encodeURIComponent(deviceId)}` : "/events";
        const response = await fetch(url, {
          headers: { Authorization: `Bearer ${tokenInput.value}` }
        });
        if (!response.ok) {
          status.textContent = `\u8b80\u53d6\u5931\u6557\uff08HTTP ${response.status}\uff09`;
          return;
        }
        const result = await response.json();
        for (const event of result.events) {
          const item = document.createElement("li");
          const details = document.createElement("pre");
          details.textContent = JSON.stringify(event, null, 2);
          item.append(details);
          eventList.append(item);
        }
                status.textContent = `\u5171 ${result.events.length} \u7b46\u4e8b\u4ef6`;
      } catch {
                status.textContent = "\u7121\u6cd5\u9023\u7dda\u81f3\u670d\u52d9";
      }
    });
  </script>
</body>
</html>
"""


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_event(payload):
    if not isinstance(payload, dict):
        return None, "invalid_json_object", "body"
    extra_fields = payload.keys() - EVENT_FIELDS
    if extra_fields:
        return None, "unknown_field", sorted(extra_fields)[0]
    for field in ("event_id", "device_id", "observed_at", "type"):
        if field not in payload:
            return None, "required", field
    event_id = payload["event_id"]
    if not isinstance(event_id, str) or not 1 <= len(event_id) <= 64 or not ID_PATTERN.fullmatch(event_id):
        return None, "invalid_value", "event_id"
    device_id = payload["device_id"]
    if not isinstance(device_id, str) or not 1 <= len(device_id) <= 32 or not ID_PATTERN.fullmatch(device_id):
        return None, "invalid_value", "device_id"
    observed_at = payload["observed_at"]
    if not isinstance(observed_at, str):
        return None, "invalid_value", "observed_at"
    try:
        parsed_time = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    except ValueError:
        return None, "invalid_value", "observed_at"
    if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
        return None, "timezone_required", "observed_at"
    if not isinstance(payload["type"], str) or payload["type"] not in EVENT_TYPES:
        return None, "invalid_value", "type"
    if "note" in payload and (not isinstance(payload["note"], str) or len(payload["note"]) > 200):
        return None, "invalid_value", "note"
    return payload, None, None


def same_content(stored, incoming):
    return all(stored.get(field) == incoming.get(field)
               for field in ("device_id", "observed_at", "type", "note"))


class StoreError(Exception):
    """Storage failed; carries only a category, never a connection string or password."""

    def __init__(self, category):
        super().__init__(category)
        self.category = category


class MemoryStore:
    """Same rules as PostgresStore, kept in memory for offline tests."""

    def __init__(self):
        self._events = {}
        self._lock = threading.Lock()

    def add(self, event):
        with self._lock:
            stored = self._events.setdefault(event["event_id"], event)
        if stored is event:
            return "created", event
        return ("same", stored) if same_content(stored, event) else ("conflict", None)

    def latest(self, limit, device_id=None):
        with self._lock:
            newest_first = sorted(reversed(list(self._events.values())),
                                  key=lambda event: event["received_at"], reverse=True)
        return [event for event in newest_first
                if device_id is None or event["device_id"] == device_id][:limit]

    def get(self, event_id):
        with self._lock:
            return self._events.get(event_id)


class PostgresStore:
    """One short TLS connection per request; every statement is parameterized."""

    CREATE_TABLE = """CREATE TABLE IF NOT EXISTS events (
        event_id text PRIMARY KEY,
        device_id text NOT NULL,
        observed_at text NOT NULL,
        type text NOT NULL,
        note text,
        received_at text NOT NULL)"""
    INSERT = """INSERT INTO events (event_id, device_id, observed_at, type, note, received_at)
        VALUES (%s, %s, %s, %s, %s, %s) ON CONFLICT (event_id) DO NOTHING"""
    SELECT = "SELECT event_id, device_id, observed_at, type, note, received_at FROM events"

    def __init__(self, environ, ca_file=RDS_CA_FILE):
        self._connection = {
            "host": environ["DB_HOST"], "port": environ.get("DB_PORT", "5432"),
            "dbname": environ["DB_NAME"], "user": environ["DB_USER"], "password": environ["DB_PASSWORD"],
            "sslmode": "verify-full", "sslrootcert": ca_file, "connect_timeout": 3,
            "options": "-c statement_timeout=3000"}
        self._schema_ready = False

    @staticmethod
    def _category(message):
        message = message.lower()
        for category, markers in (("timeout", ("timeout", "timed out")),
                                  ("authentication", ("password authentication", "pg_hba")),
                                  ("tls", ("certificate", "ssl")),
                                  ("name_resolution", ("could not translate host name",))):
            if any(marker in message for marker in markers):
                return category
        return "connection"

    def _run(self, work):
        import psycopg2  # installed on the host by the packer; not needed for offline tests
        try:
            connection = psycopg2.connect(**self._connection)
        except psycopg2.OperationalError as exc:
            # The driver's message can name the host and user, so only its category leaves here.
            raise StoreError(self._category(str(exc))) from None
        try:
            with connection, connection.cursor() as cursor:
                if not self._schema_ready:
                    cursor.execute(self.CREATE_TABLE)
                result = work(cursor)
            self._schema_ready = True  # only after the transaction that created the table committed
            return result
        except psycopg2.Error:
            raise StoreError("sql") from None
        finally:
            connection.close()

    @staticmethod
    def _event(row):
        event = dict(zip(EVENT_COLUMNS, row))
        if event["note"] is None:
            del event["note"]
        return event

    def add(self, event):
        def work(cursor):
            # The primary key decides whether this is a duplicate; there is no check-then-insert.
            cursor.execute(self.INSERT, tuple(event.get(column) for column in EVENT_COLUMNS))
            if cursor.rowcount == 1:
                return "created", event
            cursor.execute(self.SELECT + " WHERE event_id = %s", (event["event_id"],))
            stored = self._event(cursor.fetchone())
            return ("same", stored) if same_content(stored, event) else ("conflict", None)
        return self._run(work)

    def latest(self, limit, device_id=None):
        def work(cursor):
            newest_first = " ORDER BY received_at DESC, event_id DESC LIMIT %s"
            if device_id is None:
                cursor.execute(self.SELECT + newest_first, (limit,))
            else:
                cursor.execute(self.SELECT + " WHERE device_id = %s" + newest_first, (device_id, limit))
            return [self._event(row) for row in cursor.fetchall()]
        return self._run(work)

    def get(self, event_id):
        def work(cursor):
            cursor.execute(self.SELECT + " WHERE event_id = %s", (event_id,))
            row = cursor.fetchone()
            return self._event(row) if row else None
        return self._run(work)


def make_server(version_file, port=8080, store=None, environ=None):
    environ = os.environ if environ is None else environ
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    started = utc_now()
    reporter_token = environ.get("REPORTER_TOKEN", "")
    operator_token = environ.get("OPERATOR_TOKEN", "")
    auth_configured = bool(reporter_token and operator_token and reporter_token != operator_token)
    # Without the database secrets the service still starts and reports db_configured=false.
    if store is None and all(environ.get(name) for name in DB_SETTINGS):
        store = PostgresStore(environ)

    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(5)

        def send_json(self, status, body):
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def send_error_json(self, status, error, field=None):
            self.send_json(status, {"error": error, "field": field})

        def require_role(self, required_role):
            authorization = self.headers.get("Authorization", "")
            scheme, separator, presented = authorization.partition(" ")
            if not auth_configured or not separator or scheme.lower() != "bearer" or not presented:
                self.send_error_json(401, "unauthorized")
                return False
            presented_bytes = presented.encode("utf-8")
            is_reporter = hmac.compare_digest(presented_bytes, reporter_token.encode("utf-8"))
            is_operator = hmac.compare_digest(presented_bytes, operator_token.encode("utf-8"))
            if not (is_reporter or is_operator):
                self.send_error_json(401, "unauthorized")
                return False
            actual_role = "reporter" if is_reporter else "operator"
            if actual_role != required_role:
                self.send_error_json(403, "forbidden")
                return False
            return True

        def use_store(self, action):
            """Run one storage action and wrap its result in a tuple; on failure answer 503."""
            if store is None:
                self.send_error_json(503, "database_not_configured")
                return None
            try:
                return (action(store),)
            except StoreError as exc:
                print("storage error category: " + exc.category, file=sys.stderr, flush=True)
                self.send_error_json(503, "database_unavailable")
                return None

        def read_event_body(self):
            if self.headers.get_content_type() != "application/json":
                self.send_error_json(400, "content_type_must_be_application_json", "Content-Type")
                return None
            content_length = self.headers.get("Content-Length", "")
            if not re.fullmatch(r"[0-9]+", content_length):
                self.send_error_json(400, "invalid_content_length", "body")
                return None
            normalized_length = content_length.lstrip("0") or "0"
            if len(normalized_length) > 4:
                self.send_error_json(400, "body_too_large", "body")
                return None
            length = int(normalized_length)
            if length > MAX_BODY_BYTES:
                self.send_error_json(400, "body_too_large", "body")
                return None
            raw_body = self.rfile.read(length)
            if len(raw_body) != length:
                self.send_error_json(400, "incomplete_body", "body")
                return None
            try:
                return json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self.send_error_json(400, "invalid_json", "body")
                return None

        def do_GET(self):
            url = urlsplit(self.path)
            path = url.path
            if path == "/health":
                self.send_json(200, {"status": "ok", "service": "inspection", "version": version,
                                     "started_at": started, "auth_configured": auth_configured,
                                     "db_configured": store is not None})
                return
            if path == "/":
                data = INDEX_HTML.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(data)
                return
            if path == "/events" or path.startswith("/events/"):
                if not self.require_role("operator"):
                    return
                if path == "/events":
                    device_id = parse_qs(url.query).get("device_id", [None])[-1]
                    if device_id is not None and not (len(device_id) <= 32 and ID_PATTERN.fullmatch(device_id)):
                        self.send_error_json(400, "invalid_value", "device_id")
                        return
                    listed = self.use_store(lambda current: current.latest(50, device_id))
                    if listed:
                        self.send_json(200, {"events": listed[0]})
                    return
                event_id = unquote(path[len("/events/"):])
                if not ID_PATTERN.fullmatch(event_id) or len(event_id) > 64:
                    self.send_error_json(404, "not_found")
                    return
                found = self.use_store(lambda current: current.get(event_id))
                if not found:
                    return
                if found[0] is None:
                    self.send_error_json(404, "not_found")
                    return
                self.send_json(200, found[0])
                return
            self.send_error_json(404, "not_found")

        def do_POST(self):
            if self.path != "/events":
                self.send_error_json(404, "not_found")
                return
            if not self.require_role("reporter"):
                return
            payload = self.read_event_body()
            if payload is None:
                return
            validated, error, field = validate_event(payload)
            if error:
                self.send_error_json(400, error, field)
                return
            event = dict(validated)
            event["received_at"] = utc_now()
            added = self.use_store(lambda current: current.add(event))
            if not added:
                return
            outcome, stored = added[0]
            if outcome == "conflict":
                self.send_error_json(409, "duplicate_event_id", "event_id")
                return
            # A resend with identical content gets the stored event back and adds nothing.
            self.send_json(201 if outcome == "created" else 200, stored)

        def log_message(self, fmt, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
