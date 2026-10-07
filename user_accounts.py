import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


def init_user_db(db_path):
    """Create the users table if it does not already exist."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'viewer',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def create_user(db_path, username, password, display_name, role="viewer"):
    """Create a new user account."""
    password_hash = generate_password_hash(password)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, display_name, role)
            VALUES (?, ?, ?, ?)
            """,
            (username, password_hash, display_name, role),
        )
        conn.commit()


def get_user_by_username(db_path, username):
    """Retrieve a user without exposing their password hash."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            """
            SELECT id, username, display_name, role, is_active
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    return dict(user) if user else None


def authenticate_user(db_path, username, password):
    """Verify username and password and return the account if valid."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            """
            SELECT id, username, password_hash,
                   display_name, role, is_active
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()

    if not user or not user["is_active"]:
        return None

    if not check_password_hash(user["password_hash"], password):
        return None

    return {
        "id": user["id"],
        "username": user["username"],
        "display_name": user["display_name"],
        "role": user["role"],
    }

def change_user_password(db_path, username, current_password, new_password):
    """Change a user's password after verifying the current password."""

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        user = conn.execute(
            """
            SELECT id, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if not user:
            return False

        if not check_password_hash(
            user["password_hash"],
            current_password
        ):
            return False

        new_password_hash = generate_password_hash(
            new_password
        )

        conn.execute(
            """
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
            """,
            (
                new_password_hash,
                user["id"]
            )
        )

        conn.commit()

    return True


def add_email_support(db_path):
    """Add email and password-reset fields if they do not exist."""

    with sqlite3.connect(db_path) as conn:
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(users)")
        }

        if "email" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN email TEXT"
            )

        if "reset_token" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN reset_token TEXT"
            )

        if "reset_expires" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN reset_expires TEXT"
            )

        conn.commit()

def get_user_by_email(db_path, email):
    """Find an active user account by email address."""

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        user = conn.execute(
            """
            SELECT id, username, display_name, role, email
            FROM users
            WHERE LOWER(email) = LOWER(?)
              AND is_active = 1
            """,
            (email,)
        ).fetchone()

    return dict(user) if user else None


def save_reset_token(db_path, user_id, token, expires):
    """Store a temporary password-reset token."""

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE users
            SET reset_token = ?,
                reset_expires = ?
            WHERE id = ?
            """,
            (
                token,
                expires.isoformat(),
                user_id
            )
        )

        conn.commit()


def reset_password_with_token(db_path, token, new_password):
    """Reset a password using a valid, unexpired one-time token."""

    from datetime import datetime

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        user = conn.execute(
            """
            SELECT id, reset_expires
            FROM users
            WHERE reset_token = ?
              AND is_active = 1
            """,
            (token,)
        ).fetchone()

        if not user or not user["reset_expires"]:
            return False

        try:
            expires = datetime.fromisoformat(
                user["reset_expires"]
            )
        except ValueError:
            return False

        if datetime.now() > expires:
            return False

        password_hash = generate_password_hash(
            new_password
        )

        conn.execute(
            """
            UPDATE users
            SET password_hash = ?,
                reset_token = NULL,
                reset_expires = NULL
            WHERE id = ?
            """,
            (
                password_hash,
                user["id"]
            )
        )

        conn.commit()

    return True