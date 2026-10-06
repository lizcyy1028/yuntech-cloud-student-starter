#!/usr/bin/env python3
"""Small in-memory inspection event API for the W4 contract."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hmac
import json
import os
from pathlib import Path
import re
import threading
from urllib.parse import unquote, urlsplit


MAX_BODY_BYTES = 4 * 1024
EVENT_FIELDS = {"event_id", "device_id", "observed_at", "type", "note"}
ID_PATTERN = re.compile(r"[A-Za-z0-9_-]+\Z")
EVENT_TYPES = {"status", "anomaly", "test"}

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
        <button id="load-events" type="button">&#35712;&#21462;&#20107;&#20214;</button>
    <p id="status" role="status" aria-live="polite"></p>
    <ol id="events"></ol>
  </main>
  <script>
    const tokenInput = document.querySelector("#operator-token");
    const status = document.querySelector("#status");
    const eventList = document.querySelector("#events");

    document.querySelector("#load-events").addEventListener("click", async () => {
    status.textContent = "\u8f09\u5165\u4e2d\u2026";
      eventList.replaceChildren();
      try {
        const response = await fetch("/events", {
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


def make_server(version_file, port=8080):
    version = Path(version_file).read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", version):
        raise ValueError("version must contain the deployed 40-character Git commit SHA")
    started = utc_now()
    reporter_token = os.environ.get("REPORTER_TOKEN", "")
    operator_token = os.environ.get("OPERATOR_TOKEN", "")
    auth_configured = bool(reporter_token and operator_token and reporter_token != operator_token)
    events = []
    events_by_id = {}
    events_lock = threading.Lock()

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
            path = urlsplit(self.path).path
            if path == "/health":
                self.send_json(200, {"status": "ok", "service": "inspection", "version": version,
                                     "started_at": started, "auth_configured": auth_configured})
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
                    with events_lock:
                        latest = list(reversed(events[-50:]))
                    self.send_json(200, {"events": latest})
                    return
                event_id = unquote(path[len("/events/"):])
                if not ID_PATTERN.fullmatch(event_id) or len(event_id) > 64:
                    self.send_error_json(404, "not_found")
                    return
                with events_lock:
                    event = events_by_id.get(event_id)
                if event is None:
                    self.send_error_json(404, "not_found")
                    return
                self.send_json(200, event)
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
            with events_lock:
                if event["event_id"] in events_by_id:
                    self.send_error_json(409, "duplicate_event_id", "event_id")
                    return
                events.append(event)
                events_by_id[event["event_id"]] = event
            self.send_json(201, event)

        def log_message(self, fmt, *args):
            pass

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    make_server(Path(__file__).with_name("version")).serve_forever()
