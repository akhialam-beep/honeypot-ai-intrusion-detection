import os
from getpass import getpass
from pathlib import Path

from user_accounts import init_user_db, create_user, get_user_by_username


DB_PATH = Path(__file__).resolve().parent / "dashboard" / "users.db"

init_user_db(DB_PATH)

# Render / production environment variables
username = os.environ.get("ADMIN_USERNAME")
password = os.environ.get("ADMIN_PASSWORD")
display_name = os.environ.get("ADMIN_DISPLAY_NAME")

# If environment variables are not set, allow normal local terminal use
if not username:
    print("=== SugarCoated Security - Create Admin ===")
    username = input("Username: ").strip()
    display_name = input("Display name: ").strip()
    password = getpass("Password: ")
    confirm_password = getpass("Confirm password: ")

    if password != confirm_password:
        raise SystemExit("Passwords do not match.")

if not username or not display_name or not password:
    raise SystemExit("Admin username, display name, and password are required.")

existing_user = get_user_by_username(DB_PATH, username)

if existing_user:
    print(f"Admin account '{username}' already exists.")
else:
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