import getpass
import json
from pathlib import Path

import mariadb

from ai.analyzer import analyze_events


def main():
    password_file = Path.home() / ".config/honeypot-ai/db-password"

    if password_file.is_file():
        password = password_file.read_text().rstrip("\r\n")
    else:
        password = getpass.getpass("Database password: ")

    conn = mariadb.connect(
        user="cowrie_app",
        password=password,
        host="localhost",
        database="cowrie_db"
    )

    try:
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("""
                SELECT
                    timestamp,
                    source_ip AS src_ip,
                    username,
                    event_type AS eventid,
                    command AS input,
                    session_id AS session
                FROM cowrie_events
                ORDER BY id
            """)
            events = cursor.fetchall()
        finally:
            cursor.close()
    finally:
        conn.close()

    result = analyze_events(events)
    result["data_source"] = "MariaDB: cowrie_db.cowrie_events"
    result["database_rows_read"] = len(events)

    output = json.dumps(result, indent=2)

    output_dir = Path.home() / ".local/state/honeypot-ai"
    output_dir.mkdir(parents=True, exist_ok=True)

    temporary_file = output_dir / "latest_analysis.json.tmp"
    temporary_file.write_text(output + "\n", encoding="utf-8")
    temporary_file.replace(output_dir / "latest_analysis.json")

    print(output)


if __name__ == "__main__":
    main()
