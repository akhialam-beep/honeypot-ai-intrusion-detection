"""Authenticated, bounded snapshots; MariaDB on the VM remains authoritative."""
from datetime import datetime, timezone
import json
from pathlib import Path
import secrets
import sqlite3

from flask import request, abort, jsonify
from ai.analyzer import normalize_event

MAX_EVENTS = 5000
MAX_BYTES = 4 * 1024 * 1024


def register_live_data(app):
    @app.post("/api/events")
    def receive_events():
        if app.config["DATA_MODE"] != "live":
            abort(404)
        token = app.config["INGEST_TOKEN"]
        if len(token) < 32:
            abort(503, "Upload authentication is not configured.")
        expected = ("Bearer " + token).encode()
        if not secrets.compare_digest(request.headers.get("Authorization", "").encode(), expected):
            abort(401)
        request.max_content_length = MAX_BYTES
        payload = request.get_json()
        if not isinstance(payload, dict) or set(payload) != {"events"}:
            abort(400, "Expected an events snapshot.")
        rows = payload["events"]
        if not isinstance(rows, list) or len(rows) > MAX_EVENTS:
            abort(400, "Snapshot exceeds the event limit.")
        events = []
        for row in rows:
            event = normalize_event(row)
            if event is None or any(len(value) > 16384 for value in event.values()):
                abort(400, "Invalid event.")
            events.append(event)
        path = Path(app.config["LIVE_DATA_DB"])
        path.parent.mkdir(parents=True, exist_ok=True)
        received = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(path, timeout=10) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY CHECK(id=1), received TEXT NOT NULL, events TEXT NOT NULL)")
            conn.execute("INSERT OR REPLACE INTO snapshot VALUES (1, ?, ?)", (received, json.dumps(events)))
        response = jsonify(accepted=len(events), received_at=received)
        response.headers["Cache-Control"] = "no-store"
        return response


def load_live_data(app):
    batch = {"events": [], "skipped": 0, "error": None,
             "received_at": None, "stale": True}
    try:
        path = Path(app.config["LIVE_DATA_DB"])
        if not path.is_file():
            raise OSError("No snapshot")
        with sqlite3.connect(path, timeout=10) as conn:
            row = conn.execute("SELECT received, events FROM snapshot WHERE id=1").fetchone()
        if row is None:
            raise ValueError("No snapshot")
        received, serialized = row
        events = json.loads(serialized)
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(received)).total_seconds()
        batch.update(events=events, received_at=received, stale=age > 180)
    except (OSError, sqlite3.Error, ValueError, TypeError):
        batch["error"] = "Waiting for a live snapshot from the Cowrie VM."
    return batch
