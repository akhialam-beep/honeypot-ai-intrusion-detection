import json
import mariadb
import getpass

# Ask for the MariaDB password securely
db_password = getpass.getpass("Database password: ")

# Connect to the Cowrie database
conn = mariadb.connect(
    user="cowrie_app",
    password=db_password,
    host="localhost",
    database="cowrie_db"
)

cursor = conn.cursor()

# Cowrie JSON log file
log_file = "var/log/cowrie/cowrie.json"

inserted = 0

with open(log_file, "r") as file:
    for line in file:
        try:
            event = json.loads(line)

            timestamp = event.get("timestamp")
            source_ip = event.get("src_ip")
            username = event.get("username")
            event_type = event.get("eventid")
            command = event.get("input")
            session_id = event.get("session")

            cursor.execute(
                """
                INSERT IGNORE INTO cowrie_events
                (timestamp, source_ip, username, event_type, command, session_id)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    source_ip,
                    username,
                    event_type,
                    command,
                    session_id
                )
            )

            inserted += cursor.rowcount

        except json.JSONDecodeError:
            continue

conn.commit()
cursor.close()
conn.close()

print(f"Done! {inserted} Cowrie events inserted into MariaDB.")
