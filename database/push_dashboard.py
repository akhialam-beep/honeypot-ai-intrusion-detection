"""Send a recent MariaDB snapshot over HTTPS. Run with python -m database.push_dashboard."""
import json
from pathlib import Path
import sys
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward the authentication token to another URL.


def main():
    import mariadb
    config_dir = Path.home() / ".config/honeypot-ai"
    config = json.loads((config_dir / "dashboard-upload.json").read_text())
    url, token = config["url"], config["token"]
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path != "/api/events"):
        raise ValueError("Configure an HTTPS /api/events URL without credentials or query parameters.")
    if not isinstance(token, str) or len(token) < 32:
        raise ValueError("Upload token must be at least 32 characters.")
    password = (config_dir / "db-password").read_text().rstrip("\r\n")
    conn = mariadb.connect(user="cowrie_app", password=password, host="localhost", database="cowrie_db")
    try:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""SELECT timestamp, source_ip AS src_ip, username,
                event_type AS eventid, command AS input, session_id AS session
                FROM cowrie_events ORDER BY id DESC LIMIT 5000""")
            events = list(reversed(cursor.fetchall()))
        finally:
            cursor.close()
    finally:
        conn.close()
    payload = json.dumps({"events": events}).encode()
    if len(payload) > 4 * 1024 * 1024:
        raise ValueError("Snapshot exceeds 4 MiB; no upload was sent.")
    request = Request(url, data=payload, method="POST", headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + token})
    with build_opener(NoRedirect).open(request, timeout=45) as response:
        result = json.load(response)
    if result.get("accepted") != len(events):
        raise ValueError("Server did not acknowledge the complete snapshot.")
    print(f"Uploaded {len(events)} events; server received at {result['received_at']}.")


if __name__ == "__main__":
    try:
        main()
    except HTTPError as error:
        print(f"Upload failed: HTTP {error.code}. Check endpoint and token settings.", file=sys.stderr)
        sys.exit(1)
    except URLError:
        print("Upload failed: network or TLS error; the next scheduled run will retry.", file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        # Avoid including passwords, tokens, or server responses in scheduled logs.
        print(f"Upload failed ({type(error).__name__}). Check configuration and database access.", file=sys.stderr)
        sys.exit(1)
