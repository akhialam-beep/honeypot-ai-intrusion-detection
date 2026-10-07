from getpass import getpass
from pathlib import Path

from user_accounts import init_user_db, create_user


DB_PATH = Path(__file__).resolve().parent / "dashboard" / "users.db"

init_user_db(DB_PATH)

print("=== SugarCoated Security - Create Admin ===")

username = input("Username: ").strip()
display_name = input("Display name: ").strip()

password = getpass("Password: ")
confirm_password = getpass("Confirm password: ")

if not username or not display_name or not password:
    raise SystemExit("All fields are required.")

if password != confirm_password:
    raise SystemExit("Passwords do not match.")

try:
    create_user(
        DB_PATH,
        username,
        password,
        display_name,
        role="admin"
    )
except Exception as exc:
    raise SystemExit(f"Could not create account: {exc}")

print(f"Admin account '{username}' created successfully.")