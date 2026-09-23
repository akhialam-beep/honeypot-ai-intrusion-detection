"""Small, process-shared login throttle for a single hosted instance."""
from contextlib import closing
import math
from pathlib import Path
import sqlite3
import time


def reserve_login_attempt(path, bucket, limit, window):
    Path(path).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    now = time.time()
    with closing(sqlite3.connect(path, timeout=5)) as database, database:
        database.execute('CREATE TABLE IF NOT EXISTS attempts (bucket TEXT PRIMARY KEY, started REAL NOT NULL, count INTEGER NOT NULL)')
        database.execute('BEGIN IMMEDIATE')
        row = database.execute('SELECT started, count FROM attempts WHERE bucket = ?', (bucket,)).fetchone()
        if row and now - row[0] < window and row[1] >= limit:
            return max(1, math.ceil(row[0] + window - now))
        started, count = (row[0], row[1] + 1) if row and now - row[0] < window else (now, 1)
        database.execute('INSERT OR REPLACE INTO attempts VALUES (?, ?, ?)', (bucket, started, count))
    return 0


def clear_login_attempts(path, bucket):
    with closing(sqlite3.connect(path, timeout=5)) as database, database:
        database.execute('DELETE FROM attempts WHERE bucket = ?', (bucket,))
