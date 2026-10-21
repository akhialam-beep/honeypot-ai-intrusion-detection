from flask import Flask, render_template_string, request, session, redirect, url_for, abort, make_response
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter
from pathlib import Path
import sys
from datetime import datetime, timedelta
import sqlite3
import csv
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

def send_password_reset_email(recipient_email, reset_url):
    """Send a password reset link using Gmail SMTP."""

    mail_server = os.environ.get(
        "MAIL_SERVER",
        "smtp.gmail.com"
    )

    mail_port = int(
        os.environ.get("MAIL_PORT", "587")
    )

    mail_username = os.environ.get("MAIL_USERNAME")
    mail_password = os.environ.get("MAIL_PASSWORD")

    if not mail_username or not mail_password:
        raise RuntimeError(
            "Email credentials are not configured."
        )

    message = EmailMessage()

    message["Subject"] = (
        "SugarCoated Security Password Reset"
    )

    message["From"] = mail_username
    message["To"] = recipient_email

    message.set_content(
        f"""SugarCoated Security

A password reset was requested for your account.

Use the secure link below to create a new password:

{reset_url}

This link expires in 15 minutes and can only be used once.

If you did not request this password reset, you can ignore this email.

SugarCoated Security
Let's Get Sticky
"""
    )

    with smtplib.SMTP(
        mail_server,
        mail_port,
        timeout=15
    ) as smtp:

        smtp.ehlo()
        smtp.starttls()
        smtp.ehlo()

        smtp.login(
            mail_username,
            mail_password
        )

        smtp.send_message(message)

# Keep the documented `python dashboard/dashboard.py` entry point working.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ai.analyzer import analyze_events, load_event_log, detect_brute_force
from auth_security import reserve_login_attempt, clear_login_attempts
from live_data import register_live_data, load_live_data
from user_accounts import (
    init_user_db,
    authenticate_user,
    get_user_by_username,
    change_user_password,
    add_email_support,
    get_user_by_email,
    save_reset_token,
    reset_password_with_token
)

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("RENDER", "").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=8192,
    LOGIN_THROTTLE_DB=os.environ.get("LOGIN_THROTTLE_DB", os.path.join(app.instance_path, "login-attempts.sqlite3")),
    USER_DB=os.environ.get("USER_DB", os.path.join(os.path.dirname(__file__), "users.db")),
    LOGIN_ATTEMPT_LIMIT=10,
    LOGIN_WINDOW_SECONDS=60
)
   
init_user_db(app.config["USER_DB"])
add_email_support(app.config["USER_DB"])

app.config.update(
    DATA_MODE=os.environ.get("DATA_MODE", "sample"),
    INGEST_TOKEN=os.environ.get("INGEST_TOKEN", ""),
    LIVE_DATA_DB=os.environ.get("LIVE_DATA_DB", os.path.join(app.instance_path, "live-events.sqlite3")),
)
if app.config["DATA_MODE"] not in {"sample", "live"}:
    raise ValueError("DATA_MODE must be sample or live")
register_live_data(app)

DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "demo")
DEMO_PASSWORD_HASH = os.environ.get("DEMO_PASSWORD_HASH") or generate_password_hash(
    os.environ.get("DEMO_PASSWORD", "StickyDemo2026!")
)

def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def require_csrf():
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    if not expected or not secrets.compare_digest(expected.encode(), supplied.encode()):
        abort(400, "This form expired. Reload the page and try again.")


app.jinja_env.globals["csrf_token"] = csrf_token
@app.before_request
def enforce_session_timeout():
    """Sign users out after 30 minutes of inactivity."""

    if not session.get("logged_in"):
        return

    now = datetime.now()
    last_activity = session.get("last_activity")

    if last_activity:
        try:
            last_activity_time = datetime.fromisoformat(last_activity)

            if now - last_activity_time > timedelta(minutes=30):
                session.clear()
                return redirect(url_for("login"))

        except ValueError:
            session.clear()
            return redirect(url_for("login"))

    session["last_activity"] = now.isoformat()


@app.after_request
def protect_private_responses(response):
    if request.endpoint in {"dashboard", "login", "logout"}:
        response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    return response

def get_all_users(db_path):
    """Return all SugarCoated Security user accounts."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        users = conn.execute(
            """
            SELECT id, username, display_name, role,
                   is_active, created_at
            FROM users
            ORDER BY id
            """
        ).fetchall()

    return [dict(user) for user in users]


def create_dashboard_user(
    db_path,
    username,
    password,
    display_name,
    role="viewer"
):
    """Create a user from the admin dashboard."""

    if role not in {"admin", "analyst", "viewer"}:
        raise ValueError("Invalid account role.")

    password_hash = generate_password_hash(password)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO users
            (username, password_hash, display_name, role)
            VALUES (?, ?, ?, ?)
            """,
            (
                username,
                password_hash,
                display_name,
                role
            )
        )

        conn.commit()


def set_user_status(db_path, user_id, active):
    """Enable or disable a user account."""

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            UPDATE users
            SET is_active = ?
            WHERE id = ?
            """,
            (
                1 if active else 0,
                user_id
            )
        )

        conn.commit()
EVENT_LABELS = {
    "cowrie.command.input": "Command entered",
    "cowrie.login.failed": "Failed login",
    "cowrie.login.success": "Accepted login",
    "cowrie.session.connect": "New connection",
    "cowrie.session.closed": "Connection ended",
}


# ============================================================
# CONFIGURATION
# ============================================================

LOG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "sample_data",
    "cowrie.json"
)


# ============================================================
# LOAD COWRIE EVENTS
# ============================================================

def load_events():
    return load_event_log(LOG_FILE)["events"]


# ============================================================
# HTML / CSS / JAVASCRIPT
# ============================================================

HTML = """

<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        Honeypot AI Intrusion Detection
    </title>


    <!-- Google Font -->

    <link
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap"
        rel="stylesheet"
    >


    <!-- Leaflet Map -->

    <link
        rel="stylesheet"
        href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"
    >


    <!-- Font Awesome -->

    <link
        rel="stylesheet"
        href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
    >


    <!-- Chart.js -->

    <script
        src="https://cdn.jsdelivr.net/npm/chart.js"
    ></script>




<style>

/* ============================================================
   GLOBAL
   ============================================================ */

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family: "Inter", sans-serif;

    background:
        radial-gradient(
            circle at top left,
            #102a43 0%,
            #07111f 35%,
            #030712 100%
        );

    color: #e5eef8;

    min-height: 100vh;
}


/* ============================================================
   TOP NAVIGATION
   ============================================================ */

.navbar {

    height: 76px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding: 0 32px;

    border-bottom: 1px solid rgba(255,255,255,0.08);

    background:
        rgba(4, 12, 25, 0.88);

    backdrop-filter: blur(18px);

    position: sticky;

    top: 0;

    z-index: 1000;
}


.logo {

    display: flex;

    align-items: center;

    gap: 12px;
}


.logo-icon {

    width: 42px;

    height: 42px;

    display: flex;

    align-items: center;

    justify-content: center;

    border-radius: 12px;

    background:
        linear-gradient(
            135deg,
            #0ea5e9,
            #2563eb
        );

    box-shadow:
        0 0 25px rgba(14,165,233,0.4);

    font-size: 20px;
}


.logo-title {

    font-size: 18px;

    font-weight: 800;

    letter-spacing: -0.5px;
}


.logo-subtitle {

    font-size: 12px;

    color: #8ba4bd;

    margin-top: 2px;
}


.nav-links {

    display: flex;

    gap: 8px;
}


.nav-link {

    padding: 11px 15px;

    border-radius: 9px;

    color: #8da7c1;

    font-size: 13px;

    text-decoration: none;

    transition: 0.25s;
}


.nav-link:hover,
.nav-link.active {

    color: white;

    background:
        rgba(14,165,233,0.15);

    box-shadow:
        inset 0 0 15px rgba(14,165,233,0.08);
}


.system-status {

    display: flex;

    align-items: center;

    gap: 8px;

    font-size: 13px;

    color: #4ade80;
}


.status-dot {

    width: 9px;

    height: 9px;

    background: #4ade80;

    border-radius: 50%;

    box-shadow:
        0 0 12px #4ade80;

    animation: pulse 2s infinite;
}


@keyframes pulse {

    0% {
        opacity: 1;
        transform: scale(1);
    }

    50% {
        opacity: 0.5;
        transform: scale(0.8);
    }

    100% {
        opacity: 1;
        transform: scale(1);
    }
}

.status-information {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
}

.status-title {
    color: #22c55e;
    font-size: 14px;
    font-weight: 600;
}

.status-time {
    margin-top: 3px;
    color: #617990;
    font-size: 10px;
}

.logout-button {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    margin-top: 8px;
    padding: 6px 11px;
    border: 1px solid rgba(56, 189, 248, 0.4);
    border-radius: 7px;
    color: #38bdf8;
    background: rgba(56, 189, 248, 0.08);
    text-decoration: none;
    font-size: 11px;
    font-weight: 600;
    transition: 0.2s ease;
}

.logout-button:hover {
    color: #ffffff;
    background: linear-gradient(90deg, #20bfff, #7067ff);
    border-color: transparent;
    box-shadow: 0 0 14px rgba(56, 189, 248, 0.3);
}
/* ============================================================
   MAIN CONTAINER
   ============================================================ */

.container {

    max-width: 1500px;

    margin: auto;

    padding: 35px 30px 50px;
}


/* ============================================================
   HERO
   ============================================================ */

.hero {

    position: relative;

    min-height: 270px;

    padding: 40px;

    border-radius: 22px;

    overflow: hidden;

    margin-bottom: 30px;

    border:
        1px solid rgba(56,189,248,0.18);

    background:

        radial-gradient(
            circle at 75% 50%,
            rgba(14,165,233,0.18),
            transparent 35%
        ),

        linear-gradient(
            135deg,
            rgba(10,28,49,0.96),
            rgba(5,15,28,0.95)
        );

    box-shadow:
        0 20px 60px rgba(0,0,0,0.35);
}


.hero::before {

    content: "";

    position: absolute;

    width: 500px;

    height: 500px;

    right: -180px;

    top: -180px;

    border-radius: 50%;

    border: 1px solid rgba(56,189,248,0.15);

    box-shadow:
        0 0 100px rgba(14,165,233,0.15);
}


.hero-content {

    position: relative;

    z-index: 2;

    max-width: 720px;
}


.hero h1 {

    margin: 0;

    font-size: clamp(34px, 5vw, 60px);

    line-height: 1.05;

    letter-spacing: -2px;

    font-weight: 800;
}


.hero h1 span {

    background:
        linear-gradient(
            90deg,
            #38bdf8,
            #60a5fa,
            #a78bfa
        );

    -webkit-background-clip: text;

    color: transparent;
}


.hero-subtitle {

    font-size: 18px;

    color: #9db6ce;

    margin-top: 16px;

    font-weight: 500;
}


.hero-description {

    max-width: 650px;

    color: #718aa4;

    line-height: 1.7;

    margin-top: 15px;
}


.hero-badge {

    display: inline-flex;

    align-items: center;

    gap: 8px;

    padding: 8px 12px;

    border-radius: 30px;

    font-size: 12px;

    color: #7dd3fc;

    border: 1px solid rgba(56,189,248,0.2);

    background:
        rgba(14,165,233,0.08);

    margin-bottom: 18px;
}


/* ============================================================
   METRIC CARDS
   ============================================================ */

.metrics {

    display: grid;

    grid-template-columns:
        repeat(4, 1fr);

    gap: 18px;

    margin-bottom: 25px;
}


.metric {

    position: relative;

    padding: 24px;

    border-radius: 18px;

    overflow: hidden;

    border:
        1px solid rgba(255,255,255,0.08);

    background:
        linear-gradient(
            145deg,
            rgba(18,36,58,0.85),
            rgba(7,17,31,0.9)
        );

    box-shadow:
        0 15px 40px rgba(0,0,0,0.25);

    transition:
        transform 0.25s,
        border-color 0.25s;
}


.metric:hover {

    transform: translateY(-4px);

    border-color:
        rgba(56,189,248,0.35);
}


.metric-icon {

    width: 46px;

    height: 46px;

    border-radius: 13px;

    display: flex;

    align-items: center;

    justify-content: center;

    font-size: 19px;

    margin-bottom: 18px;
}


.blue {
    background: rgba(14,165,233,0.16);
    color: #38bdf8;
}

.purple {
    background: rgba(139,92,246,0.16);
    color: #a78bfa;
}

.green {
    background: rgba(16,185,129,0.16);
    color: #34d399;
}

.red {
    background: rgba(239,68,68,0.16);
    color: #f87171;
}


.metric-title {

    color: #8199b1;

    font-size: 13px;

    font-weight: 600;

    margin-bottom: 7px;
}


.metric-number {

    font-size: 32px;

    font-weight: 800;

    letter-spacing: -1px;
}


.metric-footer {

    margin-top: 10px;

    color: #607993;

    font-size: 11px;
}


.metric-line {

    position: absolute;

    bottom: 0;

    left: 0;

    height: 3px;

    width: 100%;

    background:
        linear-gradient(
            90deg,
            transparent,
            #0ea5e9,
            transparent
        );
}


/* ============================================================
   GRID
   ============================================================ */

.dashboard-grid {

    display: grid;

    grid-template-columns:
        1.55fr 0.95fr;

    gap: 20px;

    margin-bottom: 20px;
}


.card-panel {

    background:
        linear-gradient(
            145deg,
            rgba(13,31,51,0.9),
            rgba(5,15,28,0.92)
        );

    border:
        1px solid rgba(255,255,255,0.08);

    border-radius: 20px;

    padding: 22px;

    box-shadow:
        0 18px 50px rgba(0,0,0,0.25);
}


.panel-header {

    display: flex;

    align-items: center;

    justify-content: space-between;

    margin-bottom: 18px;
}


.panel-title {

    display: flex;

    align-items: center;

    gap: 10px;

    font-size: 16px;

    font-weight: 700;
}


.panel-title i {

    color: #38bdf8;
}


.panel-subtitle {

    color: #647f99;

    font-size: 11px;

    margin-top: 5px;
}


.view-all {

    color: #38bdf8;

    text-decoration: none;

    font-size: 12px;
}


/* ============================================================
   MAP
   ============================================================ */

#map {

    height: 470px;

    width: 100%;

    border-radius: 14px;

    overflow: hidden;

    border:
        1px solid rgba(255,255,255,0.08);
}


.leaflet-container {
    background:
        radial-gradient(
            circle at 50% 45%,
            rgba(14, 165, 233, 0.15),
            transparent 40%
        ),
        linear-gradient(
            135deg,
            #071b2e,
            #030b15
        );
}


.leaflet-popup-content-wrapper,
.leaflet-popup-tip {

    background: #0b1727;

    color: white;
}


.attack-marker {

    width: 16px;

    height: 16px;

    background: #ef4444;

    border-radius: 50%;

    border: 2px solid #fff;

    box-shadow:
        0 0 0 7px rgba(239,68,68,0.2),
        0 0 20px rgba(239,68,68,0.8);

    animation: markerPulse 2s infinite;
}


@keyframes markerPulse {

    0% {
        box-shadow:
            0 0 0 3px rgba(239,68,68,0.25),
            0 0 15px rgba(239,68,68,0.6);
    }

    50% {
        box-shadow:
            0 0 0 12px rgba(239,68,68,0.03),
            0 0 25px rgba(239,68,68,0.9);
    }

    100% {
        box-shadow:
            0 0 0 3px rgba(239,68,68,0.25),
            0 0 15px rgba(239,68,68,0.6);
    }
}


/* ============================================================
   CHART
   ============================================================ */

.chart-container {

    height: 280px;

    display: flex;

    align-items: center;

    justify-content: center;
}


/* ============================================================
   TABLES
   ============================================================ */

.table-container {

    overflow-x: auto;
}


table {

    width: 100%;

    border-collapse: collapse;
}


th {

    color: #718aa4;

    font-size: 11px;

    font-weight: 600;

    text-transform: uppercase;

    letter-spacing: 0.6px;

    text-align: left;

    padding: 13px;

    background:
        rgba(255,255,255,0.025);
}


td {

    padding: 13px;

    border-bottom:
        1px solid rgba(255,255,255,0.06);

    color: #c8d6e5;

    font-size: 12px;
}


tr:hover td {

    background:
        rgba(56,189,248,0.035);
}


.ip {

    font-family: monospace;

    color: #7dd3fc;
}


.badge {

    display: inline-flex;

    padding: 5px 9px;

    border-radius: 7px;

    font-size: 10px;

    font-weight: 700;
}


.badge-red {

    color: #fca5a5;

    background:
        rgba(239,68,68,0.13);

    border:
        1px solid rgba(239,68,68,0.2);
}


.badge-green {

    color: #86efac;

    background:
        rgba(34,197,94,0.12);

    border:
        1px solid rgba(34,197,94,0.2);
}


.badge-blue {

    color: #7dd3fc;

    background:
        rgba(14,165,233,0.12);

    border:
        1px solid rgba(14,165,233,0.2);
}


.badge-purple {

    color: #c4b5fd;

    background:
        rgba(139,92,246,0.12);

    border:
        1px solid rgba(139,92,246,0.2);
}


/* ============================================================
   LOWER GRID
   ============================================================ */

.three-columns {

    display: grid;

    grid-template-columns:
        1.2fr 1fr 1fr;

    gap: 20px;

    margin-bottom: 20px;
}


/* ============================================================
   PROGRESS BARS
   ============================================================ */

.progress {

    height: 6px;

    background:
        rgba(255,255,255,0.07);

    border-radius: 20px;

    overflow: hidden;

    margin-top: 5px;
}


.progress-bar {

    height: 100%;

    border-radius: 20px;

    background:
        linear-gradient(
            90deg,
            #0ea5e9,
            #6366f1
        );
}


/* ============================================================
   FOOTER
   ============================================================ */

.sticky-tagline {
    text-align: center;
    margin: -20px 0 20px;
    font-family: "Segoe Script", "Brush Script MT", cursive;
    font-size: 36px;
    font-weight: 600;
    letter-spacing: 1px;
    color: #38bdf8;
    text-shadow:
        0 0 8px rgba(56, 189, 248, 0.45),
        2px 2px 0 #6c63ff;
}
footer {

    border-top:
        1px solid rgba(255,255,255,0.07);

    padding: 25px 30px;

    display: flex;

    justify-content: space-between;

    color: #5e7690;

    font-size: 11px;
}


.footer-brand {

    color: #8ba4bd;
}


/* ============================================================
   RESPONSIVE
   ============================================================ */

@media (max-width: 1100px) {

    .metrics {

        grid-template-columns:
            repeat(2, 1fr);
    }

    .dashboard-grid {

        grid-template-columns: 1fr;
    }

    .three-columns {

        grid-template-columns: 1fr;
    }

    .nav-links {

        display: none;
    }
}


@media (max-width: 600px) {

    .container {

        padding: 20px 14px;
    }

    .navbar {

        padding: 0 15px;
    }

    .system-status {

        display: none;
    }

    .hero {

        padding: 28px 22px;
    }

    .metrics {

        grid-template-columns: 1fr;
    }

    .hero h1 {

        font-size: 36px;
    }

    #map {

        height: 350px;
    }

    footer {

        flex-direction: column;

        gap: 10px;
    }
}

</style>
<link rel="stylesheet" href="{{ url_for('static', filename='analysis.css', v='20261020a') }}">
</head>


<body>


<!-- ============================================================
     NAVBAR
     ============================================================ -->

<nav class="navbar">

    <div class="logo">

        <div class="logo-icon">
            <i class="fa-solid fa-shield-halved"></i>
        </div>

        <div>
            <div class="logo-title">
                Honeypot AI
            </div>

            <div class="logo-subtitle">
                Intrusion Detection System
            </div>
        </div>

    </div>


    <div class="nav-links">

        <a class="nav-link active" href="#dashboard">
            <i class="fa-solid fa-house"></i>
            Dashboard
        </a>

        <a class="nav-link" href="#activity">
            <i class="fa-solid fa-tower-broadcast"></i>
            Activity records
        </a>

        <a class="nav-link" href="#analytics">
            <i class="fa-solid fa-chart-line"></i>
            Analytics
        </a>

        <a class="nav-link" href="#ai-analysis">
            <i class="fa-solid fa-brain"></i>
            AI Analysis
        </a>

        <a class="nav-link" href="#map-section">
            <i class="fa-solid fa-location-dot"></i>
            IP Map
        </a>
       <a class="nav-link" href="{{ url_for('profile') }}">
    <i class="fa-solid fa-user-shield"></i>
    Profile
</a> 

    </div>


    <div class="system-status">

        <span class="status-dot"></span>

        <div class="status-information">

            <div class="status-title">
                {{ "Demo mode" if is_sample_data else "Recorded activity" }}
            </div>

            <div class="status-time">
                {{ current_time }}
            </div>

            <form action="{{ url_for('logout') }}" method="post">
                <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
                <button class="logout-button" type="submit">Log out</button>
            </form>

        </div>

    </div>

</nav>


<!-- ============================================================
     MAIN
     ============================================================ -->

<div class="container" id="dashboard">



<!-- ============================================================
     HERO
     ============================================================ -->

<section class="hero">

    <div class="hero-content">

        <div class="hero-badge">

            <i class="fa-solid fa-circle-nodes"></i>

            COWRIE HONEYPOT • AI ANALYSIS

        </div>


        <h1>

            Honeypot
            <span>AI Intrusion Detection</span>

        </h1>


        <div class="hero-subtitle">

            Understand suspicious activity, one step at a time.

        </div>


        <div class="hero-description">

            A honeypot is a test system that records connection attempts.
            Explore {{ 'example' if is_sample_data else 'recorded' }} activity and see what needs a closer look.

        </div>

    </div>

</section>



{% if live_mode %}
<section class="hero-description" role="status">
    <strong>MariaDB snapshot — latest 5,000 events maximum.</strong><br>
    {% if log_batch.received_at %}
        Last received (UTC): {{ log_batch.received_at }}.<br>
        {{ "Updates delayed: no upload in over 3 minutes. Showing the last received snapshot." if log_batch.stale else "Receiving VM updates." }}
    {% else %}
        Waiting for the first VM upload. Sample events are not shown in live mode.
    {% endif %}
</section>
{% endif %}

<!-- ============================================================
     METRICS
     ============================================================ -->


<!-- SYSTEM HEALTH MONITORING -->
<section class="card-panel" id="system-health"
         style="margin-bottom:25px;">

    <div class="panel-header">
        <div class="panel-title">
            <i class="fa-solid fa-heart-pulse"></i>
            System Health
        </div>

        <span class="badge
            {% if system_health.status == 'Receiving Events' %}
                badge-green
            {% elif system_health.status == 'Updates Delayed' %}
                badge-red
            {% else %}
                badge-blue
            {% endif %}">
            {{ system_health.status }}
        </span>
    </div>

    <div class="table-container">
        <table>
            <tbody>
                <tr>
                    <td>Data Source</td>
                    <td>{{ system_health.data_source }}</td>
                </tr>
                <tr>
                    <td>Last Successful Upload (UTC)</td>
                    <td>
                        {{ system_health.last_upload or 'Not available' }}
                    </td>
                </tr>
                <tr>
                    <td>Monitoring Status</td>
                    <td>{{ system_health.detail }}</td>
                </tr>
            </tbody>
        </table>
    </div>
</section>



<!-- BRUTE-FORCE ALERTS -->
<section class="card-panel" id="brute-force-alerts" style="margin-bottom:25px;">
  <div class="panel-header">
    <div class="panel-title">
      <i class="fa-solid fa-shield-halved"></i>
      Brute-Force Alerts
    </div>
    <span class="badge {% if brute_force_alerts %}badge-red{% else %}badge-green{% endif %}">
      {{ brute_force_alerts|length }} alert{{ '' if brute_force_alerts|length == 1 else 's' }}
    </span>
  </div>

  {% if total_events == 0 %}
    <p>No events available to evaluate yet.</p>
  {% elif brute_force_alerts %}
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Source IP</th>
            <th>Failed Attempts</th>
            <th>First to Last Attempt</th>
          </tr>
        </thead>
        <tbody>
          {% for alert in brute_force_alerts %}
          <tr>
            <td><span class="badge badge-red">{{ alert.severity }}</span></td>
            <td>{{ alert.ip }}</td>
            <td>{{ alert.count }}</td>
            <td>{{ alert.first_attempt }} – {{ alert.last_attempt }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
  {% else %}
    <p>No brute-force patterns detected in the available events.</p>
  {% endif %}
</section>
{% include "ai_analysis.html" %}

<!-- ============================================================
     MAP + CHART
     ============================================================ -->

<div class="dashboard-grid">


    <!-- MAP -->

    <section class="card-panel" id="map-section">

        <div class="panel-header">

            <div>

                <div class="panel-title">

                    <i class="fa-solid fa-location-dot"></i>

                    Example connection locations

                </div>

                <div class="panel-subtitle">

                    Preset map points for the demo — not verified locations

                </div>

            </div>

        </div>


        <div id="map"></div>

    </section>



    <!-- EVENT CHART -->

    <section class="card-panel" id="analytics">

        <div class="panel-header">

            <div>

                <div class="panel-title">

                    <i class="fa-solid fa-chart-pie"></i>

                    Event Types

                </div>

                <div class="panel-subtitle">

                    Distribution of honeypot activity

                </div>

            </div>

        </div>


        <div class="chart-container">

            <canvas id="eventChart"></canvas>

        </div>

    </section>


</div>



<!-- ============================================================
     TOP SOURCE IP
     ============================================================ -->

<section class="card-panel" style="margin-bottom:20px;">

    <div class="panel-header">

        <div>

            <div class="panel-title">

                <i class="fa-solid fa-wifi"></i>

                Top Source IP Addresses

            </div>

            <div class="panel-subtitle">

                IP addresses generating the most honeypot events

            </div>

        </div>

    </div>


    <div class="table-container">

        <table>

            <thead>

                <tr>

                    <th>#</th>

                    <th>Source IP</th>

                    <th>Events</th>

                    <th>Activity</th>

                </tr>

            </thead>


            <tbody>

                {% for ip, count in source_ips %}

                <tr>

                    <td>
                        {{ loop.index }}
                    </td>

                    <td class="ip">
                        {{ ip }}
                    </td>

                    <td>
                        {{ count }}
                    </td>

                    <td>

                        <div class="progress">

                            <div
                                class="progress-bar"
                                style="
                                    width:
                                    {{ (count / max_ip_count * 100)
                                    if max_ip_count else 0 }}%;
                                "
                            ></div>

                        </div>

                    </td>

                </tr>

                {% endfor %}

            </tbody>

        </table>

    </div>

</section>



<!-- ============================================================
     THREE COLUMN SECTION
     ============================================================ -->

{% include "activity.html" %}

<div class="three-columns secondary-tables">

    <!-- LOGIN ATTEMPTS -->

    <section class="card-panel">

        <div class="panel-header">

            <div class="panel-title">

                <i class="fa-solid fa-user-lock"></i>

                Login Attempts

            </div>

        </div>


        <div class="table-container">

            <table>

                <thead>

                    <tr>

                        <th>Username</th>

                        <th>Source IP</th>

                        <th>Result</th>

                    </tr>

                </thead>


                <tbody>

                    {% for login in login_events %}

                    <tr>

                        <td>
                            {{ login.username }}
                        </td>

                        <td class="ip">
                            {{ login.src_ip }}
                        </td>

                        <td>

                            {% if login.eventid == "cowrie.login.success" %}

                                <span class="badge badge-green">
                                    Success
                                </span>

                            {% else %}

                                <span class="badge badge-red">
                                    Failed
                                </span>

                            {% endif %}

                        </td>

                    </tr>

                    {% endfor %}

                </tbody>

            </table>

        </div>

    </section>



    <!-- COMMANDS -->

    <section class="card-panel">

        <div class="panel-header">

            <div class="panel-title">

                <i class="fa-solid fa-terminal"></i>

                Most Common Commands

            </div>

        </div>


        <div class="table-container">

            <table>

                <thead>

                    <tr>

                        <th>Command</th>

                        <th>Count</th>

                        <th>Activity</th>

                    </tr>

                </thead>


                <tbody>

                    {% for command, count in commands_list %}

                    <tr>

                        <td>
                            {{ command }}
                        </td>

                        <td>
                            {{ count }}
                        </td>

                        <td>

                            <div class="progress">

                                <div
                                    class="progress-bar"
                                    style="
                                    width:
                                    {{ (count / max_command_count * 100)
                                    if max_command_count else 0 }}%;
                                    "
                                ></div>

                            </div>

                        </td>

                    </tr>

                    {% endfor %}

                </tbody>

            </table>

        </div>

    </section>


</div>



</div>



<!-- ============================================================
     FOOTER
     ============================================================ -->

<div class="sticky-tagline">Let’s Get Sticky</div>
<footer>

    <div class="footer-brand">

        🐝 Honeypot AI Intrusion Detection

        <span style="margin:0 8px;">|</span>

        Powered by Cowrie + Python + Flask

    </div>


    <div>

        Dashboard &nbsp; • &nbsp;
        Analytics &nbsp; • &nbsp;
        IP Map

    </div>

</footer>



<!-- ============================================================
     LEAFLET
     ============================================================ -->

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>


<script>

/* ============================================================
   MAP
   ============================================================ */

const map = L.map("map", {
    center: [20, 0],
    zoom: 2,
    minZoom: 1,
    maxZoom: 8,
    worldCopyJump: true,
    zoomControl: true
});

// Load the world map from our own project.
// No external map tile provider or API key is required.
fetch("{{ url_for('static', filename='countries.geo.json') }}")
    .then(response => {
        if (!response.ok) {
            throw new Error("World map could not be loaded.");
        }

        return response.json();
    })
    .then(worldData => {

        const worldLayer = L.geoJSON(worldData, {

            style: function() {
                return {
                    color: "#2684b8",
                    weight: 1,
                    opacity: 0.75,
                    fillColor: "#0b2940",
                    fillOpacity: 0.85
                };
            },

            onEachFeature: function(feature, layer) {

                if (
                    feature.properties &&
                    feature.properties.name
                ) {
                    layer.bindTooltip(
                        feature.properties.name,
                        {
                            sticky: true
                        }
                    );
                }
            }

        }).addTo(map);

        map.fitBounds(
            worldLayer.getBounds(),
            {
                padding: [10, 10]
            }
        );
    })
    .catch(error => {
        console.error(
            "World map error:",
            error
        );
    });


const attackerLocations =
    {{ attacker_locations | tojson }};


attackerLocations.forEach(function(location) {

    const icon = L.divIcon({

        className: "",

        html:
            '<div class="attack-marker"></div>',

        iconSize: [16, 16],

        iconAnchor: [8, 8]

    });


    L.marker(
        [
            location.lat,
            location.lng
        ],
        {
            icon: icon
        }
    )

    .addTo(map)

    .bindPopup(`

        <div style="min-width:190px">

            <strong>
                <i class="fa-solid fa-triangle-exclamation"></i>
                Source IP Activity
            </strong>

            <br><br>

            <strong>IP:</strong>
            ${location.ip}

            <br>

            <strong>Events:</strong>
            ${location.events}

            <br>

            <strong>Location:</strong>
            ${location.location}

        </div>

    `);

});



/* ============================================================
   EVENT CHART
   ============================================================ */

const eventLabels =
    {{ event_labels | tojson }};

const eventValues =
    {{ event_values | tojson }};


const ctx =
    document
    .getElementById("eventChart")
    .getContext("2d");


new Chart(ctx, {

    type: "doughnut",

    data: {

        labels: eventLabels,

        datasets: [{

            data: eventValues,

            borderWidth: 0,

            backgroundColor: [

                "#0ea5e9",
                "#ef4444",
                "#22c55e",
                "#f59e0b",
                "#8b5cf6",
                "#06b6d4"

            ],

            hoverOffset: 8

        }]

    },

    options: {

        responsive: true,

        maintainAspectRatio: false,

        cutout: "72%",

        plugins: {

            legend: {

                position: "bottom",

                labels: {

                    color: "#8ba4bd",

                    padding: 16,

                    usePointStyle: true,

                    font: {
                        size: 11
                    }

                }

            }

        }

    }

});


/* ============================================================
   AUTO REFRESH
   ============================================================ */

/*
   Refresh the dashboard every 60 seconds.

   You can remove this if you don't want automatic refresh.
*/

setInterval(function() {
    // Keep expanded evidence and keyboard focus intact while someone is reading.
    if (document.visibilityState === "visible" &&
        !document.querySelector("details[open], input:focus, select:focus, button:focus, #ai-analysis:focus-within")) {
        location.reload();
    }
}, 60000);

</script>


</body>

</html>

"""
PROFILE_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SugarCoated Security | My Profile</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            margin: 0;
            background: radial-gradient(circle at top, #10243c 0%, #040b16 55%);
            color: white;
            font-family: Arial, sans-serif;
        }

        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 40px;
            background: #07111f;
            border-bottom: 1px solid rgba(255,255,255,.12);
        }

        .brand {
            font-size: 20px;
            font-weight: bold;
        }

        .brand span {
            color: #63b3ff;
        }

        .back-button {
            color: white;
            text-decoration: none;
            padding: 10px 16px;
            border: 1px solid #3288d8;
            border-radius: 8px;
        }

        .container {
            width: min(760px, 92%);
            margin: 60px auto;
        }

        .profile-card {
            padding: 35px;
            border: 1px solid rgba(99,179,255,.35);
            border-radius: 18px;
            background: rgba(10,25,44,.94);
        }

        .profile-header {
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 30px;
        }

        .avatar {
            width: 76px;
            height: 76px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: #3288d8;
            font-size: 30px;
            font-weight: bold;
        }

        h1 {
            margin: 0 0 6px;
        }

        .role {
            color: #63b3ff;
            text-transform: capitalize;
        }

        .profile-row {
            padding: 18px 0;
            border-top: 1px solid rgba(255,255,255,.10);
        }

        .label {
            color: #8fa6bd;
            font-size: 12px;
            margin-bottom: 6px;
        }

        .value {
            font-size: 17px;
        }

        .active {
            color: #69e6a6;
            font-weight: bold;
        }

        .security {
            margin-top: 28px;
            padding: 22px;
            border-radius: 12px;
            background: rgba(50,136,216,.08);
            border: 1px solid rgba(50,136,216,.25);
        }
    </style>
</head>

<body>

<nav class="navbar">
    <div class="brand">
        SugarCoated <span>Security</span>
    </div>

    <a class="back-button" href="{{ url_for('dashboard') }}">
        Back to Dashboard
    </a>
</nav>

<main class="container">

    <div class="profile-card">

        <div class="profile-header">

            <div class="avatar">
                {{ user.display_name[0] | upper }}
            </div>

            <div>
                <h1>{{ user.display_name }}</h1>
                <div class="role">
                    {{ user.role }}
                </div>
            </div>

        </div>

        <div class="profile-row">
            <div class="label">DISPLAY NAME</div>
            <div class="value">{{ user.display_name }}</div>
        </div>

        <div class="profile-row">
            <div class="label">USERNAME</div>
            <div class="value">{{ user.username }}</div>
        </div>

        <div class="profile-row">
            <div class="label">ROLE</div>
            <div class="value">{{ user.role | capitalize }}</div>
        </div>

        <div class="profile-row">
            <div class="label">ACCOUNT STATUS</div>

            {% if user.is_active %}
                <div class="value active">● Active</div>
            {% else %}
                <div class="value">Inactive</div>
            {% endif %}
        </div>

        <div class="security">
            <h2>Account Security</h2>
            <p>
                Individual database-backed account authentication is enabled.
            </p>
            <a href="{{ url_for('change_password') }}"
   style="
       display:inline-block;
       margin-top:16px;
       padding:10px 16px;
       background:#3288d8;
       color:white;
       text-decoration:none;
       border-radius:8px;
   ">
    Change Password
</a>

{% if user.role == "admin" %}
<a href="{{ url_for('admin_users') }}"
   style="
       display:inline-block;
       margin-top:16px;
       margin-left:8px;
       padding:10px 16px;
       border:1px solid #3288d8;
       color:white;
       text-decoration:none;
       border-radius:8px;
   ">
    Manage Users
</a>
{% endif %}
        </div>

    </div>

</main>

</body>
</html>
"""

ADMIN_USERS_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SugarCoated Security | User Management</title>

    <style>
        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            background:
                radial-gradient(circle at top, #10243c 0%, #040b16 55%);
            color: white;
            font-family: Arial, sans-serif;
        }

        .navbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 40px;
            background: #07111f;
            border-bottom: 1px solid rgba(255,255,255,.12);
        }

        .brand {
            font-size: 20px;
            font-weight: bold;
        }

        .brand span { color: #63b3ff; }

        .nav-actions {
            display: flex;
            gap: 10px;
        }

        .button {
            display: inline-block;
            padding: 10px 16px;
            border: 1px solid #3288d8;
            border-radius: 8px;
            background: #3288d8;
            color: white;
            text-decoration: none;
            cursor: pointer;
        }

        .button.secondary {
            background: transparent;
        }

        .container {
            width: min(1100px, 94%);
            margin: 50px auto;
        }

        .heading {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
        }

        h1 { margin: 0; }

        .subtitle {
            color: #8fa6bd;
            margin-top: 7px;
        }

        .card {
            background: rgba(10,25,44,.94);
            border: 1px solid rgba(99,179,255,.30);
            border-radius: 18px;
            overflow: hidden;
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th {
            padding: 16px;
            text-align: left;
            color: #8fa6bd;
            font-size: 12px;
            background: #071524;
        }

        td {
            padding: 17px 16px;
            border-top: 1px solid rgba(255,255,255,.08);
        }

        .role {
            display: inline-block;
            padding: 6px 10px;
            border-radius: 20px;
            background: rgba(50,136,216,.15);
            color: #63b3ff;
            text-transform: capitalize;
        }

        .active {
            color: #69e6a6;
            font-weight: bold;
        }

        .inactive {
            color: #ff858d;
            font-weight: bold;
        }

        .small-button {
            border: 1px solid #3288d8;
            border-radius: 7px;
            padding: 7px 11px;
            background: transparent;
            color: #63b3ff;
            cursor: pointer;
        }

        .small-button:hover {
            background: #3288d8;
            color: white;
        }

        @media(max-width: 700px) {
            .navbar, .heading {
                flex-direction: column;
                align-items: flex-start;
                gap: 15px;
            }

            .card {
                overflow-x: auto;
            }
        }
    </style>
</head>

<body>

<nav class="navbar">

    <div class="brand">
        SugarCoated <span>Security</span>
    </div>

    <div class="nav-actions">

        <a class="button secondary"
           href="{{ url_for('profile') }}">
            My Profile
        </a>

        <a class="button secondary"
           href="{{ url_for('dashboard') }}">
            Dashboard
        </a>

    </div>

</nav>


<main class="container">

    <div class="heading">

        <div>
            <h1>User Management</h1>

            <div class="subtitle">
                Manage SugarCoated Security access and roles.
            </div>
        </div>

        <a class="button"
           href="{{ url_for('create_user') }}">
            + Create Account
        </a>

    </div>


    <div class="card">

        <table>

            <thead>
                <tr>
                    <th>DISPLAY NAME</th>
                    <th>USERNAME</th>
                    <th>ROLE</th>
                    <th>STATUS</th>
                    <th>CREATED</th>
                    <th>ACTION</th>
                </tr>
            </thead>

            <tbody>

            {% for account in users %}

                <tr>

                    <td>
                        {{ account.display_name }}
                    </td>

                    <td>
                        {{ account.username }}
                    </td>

                    <td>
                        <span class="role">
                            {{ account.role }}
                        </span>
                    </td>

                    <td>

                        {% if account.is_active %}

                            <span class="active">
                                ● Active
                            </span>

                        {% else %}

                            <span class="inactive">
                                ● Disabled
                            </span>

                        {% endif %}

                    </td>

                    <td>
                        {{ account.created_at }}
                    </td>

                    <td>

                    {% if account.id == session.get("user_id") %}

                        Current account

                    {% else %}

                        <form
                            method="POST"
                            action="{{ url_for('toggle_user', user_id=account.id) }}"
                        >

                            <input
                                type="hidden"
                                name="csrf_token"
                                value="{{ csrf_token() }}"
                            >

                            {% if account.is_active %}

                                <input
                                    type="hidden"
                                    name="active"
                                    value="0"
                                >

                                <button
                                    class="small-button"
                                    type="submit"
                                >
                                    Disable
                                </button>

                            {% else %}

                                <input
                                    type="hidden"
                                    name="active"
                                    value="1"
                                >

                                <button
                                    class="small-button"
                                    type="submit"
                                >
                                    Enable
                                </button>

                            {% endif %}

                        </form>

                    {% endif %}

                    </td>

                </tr>

            {% endfor %}

            </tbody>

        </table>

    </div>

</main>

</body>
</html>
"""


CREATE_USER_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        SugarCoated Security | Create Account
    </title>

    <style>

        * { box-sizing: border-box; }

        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;

            background:
                radial-gradient(
                    circle at top,
                    #10243c 0%,
                    #040b16 55%
                );

            color: white;
            font-family: Arial, sans-serif;
        }

        .card {
            width: min(500px, 92%);
            padding: 35px;
            background: rgba(10,25,44,.96);
            border: 1px solid rgba(99,179,255,.35);
            border-radius: 18px;
        }

        h1 {
            margin-top: 0;
        }

        .subtitle {
            color: #8fa6bd;
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin: 15px 0 7px;
            color: #b9d5ed;
        }

        input,
        select {
            width: 100%;
            padding: 12px 13px;
            border-radius: 9px;
            border: 1px solid #24435f;
            background: #071524;
            color: white;
        }

        input:focus,
        select:focus {
            outline: none;
            border-color: #38bdf8;
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 13px;
            border: 0;
            border-radius: 9px;
            background:
                linear-gradient(
                    90deg,
                    #20bfff,
                    #7067ff
                );
            color: white;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
        }

        .error {
            padding: 11px;
            margin-bottom: 15px;
            border-radius: 8px;
            background: rgba(255,94,104,.12);
            color: #ff858d;
        }

        .back {
            display: block;
            margin-top: 18px;
            text-align: center;
            color: #63b3ff;
            text-decoration: none;
        }

    </style>

</head>

<body>

<form class="card" method="POST">

    <input
        type="hidden"
        name="csrf_token"
        value="{{ csrf_token() }}"
    >

    <h1>Create Account</h1>

    <div class="subtitle">
        Add a SugarCoated Security team member.
    </div>


    {% if error %}

        <div class="error">
            {{ error }}
        </div>

    {% endif %}


    <label>
        Display Name
    </label>

    <input
        name="display_name"
        required
        maxlength="100"
    >


    <label>
        Username
    </label>

    <input
        name="username"
        required
        maxlength="128"
        autocomplete="off"
    >


    <label>
        Temporary Password
    </label>

    <input
        name="password"
        type="password"
        required
        minlength="12"
        autocomplete="new-password"
    >


    <label>
        Account Role
    </label>

    <select name="role">

        <option value="viewer">
            Viewer
        </option>

        <option value="analyst">
            Analyst
        </option>

        <option value="admin">
            Administrator
        </option>

    </select>


    <button type="submit">
        Create Account
    </button>


    <a
        class="back"
        href="{{ url_for('admin_users') }}"
    >
        ← Back to User Management
    </a>

</form>

</body>
</html>
"""
CHANGE_PASSWORD_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SugarCoated Security | Change Password</title>

    <style>
        * { box-sizing: border-box; }

        body {
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            background: radial-gradient(circle at top, #10243c 0%, #040b16 55%);
            color: white;
            font-family: Arial, sans-serif;
        }

        .card {
            width: min(500px, 92%);
            padding: 35px;
            background: rgba(10,25,44,.96);
            border: 1px solid rgba(99,179,255,.35);
            border-radius: 18px;
        }

        h1 { margin-top: 0; }

        .subtitle {
            color: #8fa6bd;
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin: 16px 0 7px;
            color: #b9d5ed;
        }

        input {
            width: 100%;
            padding: 13px;
            border-radius: 9px;
            border: 1px solid #24435f;
            background: #071524;
            color: white;
        }

        input:focus {
            outline: none;
            border-color: #38bdf8;
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 13px;
            border: 0;
            border-radius: 9px;
            background: linear-gradient(90deg, #20bfff, #7067ff);
            color: white;
            font-size: 15px;
            font-weight: bold;
            cursor: pointer;
        }

        .message {
            padding: 11px;
            margin-bottom: 15px;
            border-radius: 8px;
        }

        .error {
            background: rgba(255,94,104,.12);
            color: #ff858d;
        }

        .success {
            background: rgba(105,230,166,.12);
            color: #69e6a6;
        }

        .back {
            display: block;
            margin-top: 18px;
            text-align: center;
            color: #63b3ff;
            text-decoration: none;
        }
    </style>
</head>

<body>

<form class="card" method="POST">

    <input type="hidden"
           name="csrf_token"
           value="{{ csrf_token() }}">

    <h1>Change Password</h1>

    <div class="subtitle">
        Update your SugarCoated Security credentials.
    </div>

    {% if error %}
        <div class="message error">{{ error }}</div>
    {% endif %}

    {% if success %}
        <div class="message success">{{ success }}</div>
    {% endif %}

    <label>Current Password</label>
    <input
        name="current_password"
        type="password"
        required
        autocomplete="current-password"
    >

    <label>New Password</label>
    <input
        name="new_password"
        type="password"
        required
        minlength="12"
        autocomplete="new-password"
    >

    <label>Confirm New Password</label>
    <input
        name="confirm_password"
        type="password"
        required
        minlength="12"
        autocomplete="new-password"
    >

    <button type="submit">
        Update Password
    </button>

    <a class="back" href="{{ url_for('profile') }}">
        ← Back to My Profile
    </a>

</form>

</body>
</html>
"""

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Honeypot AI Login</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            background:
                radial-gradient(circle at top, #10243c 0%, #040b16 55%);
            color: #ffffff;
            font-family: Arial, sans-serif;
        }

        .login-card {
            width: min(420px, 90%);
            padding: 40px;
            background: rgba(8, 24, 42, 0.95);
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 22px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.45);
        }

        .shield {
            width: 58px;
            height: 58px;
            margin: 0 auto 18px;
            display: grid;
            place-items: center;
            border-radius: 16px;
            background: linear-gradient(135deg, #20bfff, #7067ff);
            font-size: 28px;
        }

        h1 {
            margin: 0;
            text-align: center;
            font-size: 26px;
        }

        .subtitle {
            margin: 8px 0 28px;
            text-align: center;
            color: #7ca6ce;
        }

        label {
            display: block;
            margin: 16px 0 7px;
            color: #b9d5ed;
            font-size: 14px;
        }

        input {
            width: 100%;
            padding: 13px 14px;
            border: 1px solid #24435f;
            border-radius: 10px;
            background: #071524;
            color: white;
            font-size: 15px;
            outline: none;
        }

        input:focus {
            border-color: #38bdf8;
            box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.12);
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 13px;
            border: 0;
            border-radius: 10px;
            background: linear-gradient(90deg, #20bfff, #7067ff);
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }

        .error {
            margin: 0 0 15px;
            padding: 10px;
            border: 1px solid #ff5e68;
            border-radius: 8px;
            background: rgba(255, 94, 104, 0.12);
            color: #ff858d;
            text-align: center;
        }
    </style>
</head>

<body>
    <form class="login-card" method="POST">
        <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
        <div class="shield">🛡️</div>
        <h1>Honeypot AI</h1>
        <p class="subtitle">Security activity dashboard</p>

        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}

        <label for="username">Username</label>
        <input id="username" name="username" required maxlength="128" autocomplete="username">

        <label for="password">Password</label>
        <input id="password" name="password" type="password"
               required maxlength="1024" autocomplete="current-password">

        <button type="submit">Sign In</button>
        <a href="{{ url_for('forgot_password') }}"
   style="
       display:block;
       margin-top:18px;
       text-align:center;
       color:#63b3ff;
       text-decoration:none;
   ">
    Forgot Password?
</a>
    </form>
</body>
</html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        require_csrf()

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if len(username) > 128 or len(password) > 1024:
            abort(400, "Username or password is too long.")

        # Check whether this username exists in the user database.
        user = get_user_by_username(
            app.config["USER_DB"],
            username
        )

        valid_username = user is not None
        bucket = "account" if valid_username else "unknown"

        # Preserve the team's existing login throttling.
        try:
            retry = reserve_login_attempt(
                app.config["LOGIN_THROTTLE_DB"],
                bucket,
                app.config["LOGIN_ATTEMPT_LIMIT"],
                app.config["LOGIN_WINDOW_SECONDS"],
            )
        except sqlite3.Error:
            return render_template_string(
                LOGIN_PAGE,
                error="Sign-in is temporarily unavailable. Please try again shortly.",
            ), 503

        if retry:
            response = make_response(
                render_template_string(
                    LOGIN_PAGE,
                    error=f"Too many sign-in attempts. Try again in {retry} seconds.",
                ),
                429,
            )
            response.headers["Retry-After"] = str(retry)
            return response

        # Authenticate against the individual user account database.
        authenticated_user = authenticate_user(
            app.config["USER_DB"],
            username,
            password,
        )

        if authenticated_user:
            clear_login_attempts(
                app.config["LOGIN_THROTTLE_DB"],
                bucket,
            )

            session.clear()
            session.permanent = True
            session["logged_in"] = True
            session["user_id"] = authenticated_user["id"]
            session["username"] = authenticated_user["username"]
            session["display_name"] = authenticated_user["display_name"]
            session["role"] = authenticated_user["role"]

            csrf_token()

            return redirect(url_for("dashboard"))

        error = "Incorrect username or password."

    return render_template_string(LOGIN_PAGE, error=error)
@app.route("/profile")
def profile():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    user = get_user_by_username(
        app.config["USER_DB"],
        session.get("username")
    )

    if not user:
        session.clear()
        return redirect(url_for("login"))

    return render_template_string(
        PROFILE_PAGE,
        user=user
    )


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    error = None
    success = None

    if request.method == "POST":
        require_csrf()

        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        user = get_user_by_username(
            app.config["USER_DB"],
            session.get("username")
        )

        if not user or not check_password_hash(
            user["password_hash"], current_password
        ):
            error = "Current password is incorrect."

        elif len(new_password) < 8:
            error = "New password must be at least 8 characters."

        elif new_password != confirm_password:
            error = "New passwords do not match."

        else:
            change_user_password(
                app.config["USER_DB"],
                session.get("username"),
                new_password
            )
            success = "Password changed successfully."

    return render_template_string(
        CHANGE_PASSWORD_PAGE,
        error=error,
        success=success
    )
@app.route("/admin/users")
def admin_users():

    # User must be signed in.
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    # Only administrators can manage accounts.
    if session.get("role") != "admin":
        abort(403)

    users = get_all_users(
        app.config["USER_DB"]
    )

    return render_template_string(
        ADMIN_USERS_PAGE,
        users=users
    )


@app.route("/admin/users/create", methods=["GET", "POST"])
def create_user():

    # User must be signed in.
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    # Only administrators can create accounts.
    if session.get("role") != "admin":
        abort(403)

    error = None

    if request.method == "POST":

        require_csrf()

        display_name = request.form.get(
            "display_name",
            ""
        ).strip()

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        role = request.form.get(
            "role",
            "viewer"
        )


        if not display_name or not username or not password:

            error = "All fields are required."


        elif len(password) < 12:

            error = (
                "Temporary password must be "
                "at least 12 characters."
            )


        elif role not in {
            "admin",
            "analyst",
            "viewer"
        }:

            error = "Invalid account role."


        else:

            try:

                create_dashboard_user(
                    app.config["USER_DB"],
                    username,
                    password,
                    display_name,
                    role
                )

                return redirect(
                    url_for("admin_users")
                )


            except sqlite3.IntegrityError:

                error = (
                    "That username already exists."
                )


    return render_template_string(
        CREATE_USER_PAGE,
        error=error
    )


@app.route(
    "/admin/users/<int:user_id>/status",
    methods=["POST"]
)
def toggle_user(user_id):

    # User must be signed in.
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    # Only administrators can enable/disable accounts.
    if session.get("role") != "admin":
        abort(403)

    require_csrf()

    # Prevent an administrator from disabling
    # the account they are currently using.
    if user_id == session.get("user_id"):

        abort(
            400,
            "You cannot disable your own signed-in account."
        )


    active = (
        request.form.get("active") == "1"
    )

    set_user_status(
        app.config["USER_DB"],
        user_id,
        active
    )

    return redirect(
        url_for("admin_users")
    )

FORGOT_PASSWORD_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SugarCoated Security | Forgot Password</title>

    <style>
        * { box-sizing: border-box; }

        body {
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            background: radial-gradient(circle at top, #10243c 0%, #040b16 55%);
            color: white;
            font-family: Arial, sans-serif;
        }

        .card {
            width: min(480px, 92%);
            padding: 35px;
            background: rgba(10,25,44,.96);
            border: 1px solid rgba(99,179,255,.35);
            border-radius: 18px;
        }

        h1 { margin-top: 0; }

        .subtitle {
            color: #8fa6bd;
            margin-bottom: 25px;
            line-height: 1.5;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #b9d5ed;
        }

        input {
            width: 100%;
            padding: 13px;
            border-radius: 9px;
            border: 1px solid #24435f;
            background: #071524;
            color: white;
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 13px;
            border: 0;
            border-radius: 9px;
            background: linear-gradient(90deg, #20bfff, #7067ff);
            color: white;
            font-weight: bold;
            cursor: pointer;
        }

        .message {
            margin-bottom: 18px;
            padding: 12px;
            border-radius: 8px;
            background: rgba(105,230,166,.12);
            color: #69e6a6;
        }

        .back {
            display: block;
            margin-top: 20px;
            text-align: center;
            color: #63b3ff;
            text-decoration: none;
        }
    </style>
</head>

<body>

<form class="card" method="POST">

    <input
        type="hidden"
        name="csrf_token"
        value="{{ csrf_token() }}"
    >

    <h1>Forgot Password?</h1>

    <div class="subtitle">
        Enter the email address associated with your
        SugarCoated Security account.
    </div>

    {% if message %}
        <div class="message">{{ message }}</div>
    {% endif %}

    <label>Email Address</label>

    <input
        type="email"
        name="email"
        placeholder="name@example.com"
        autocomplete="email"
        required
    >

    <button type="submit">
        Send Reset Link
    </button>

    <a class="back" href="{{ url_for('login') }}">
        ← Return to Login
    </a>

</form>

</body>
</html>
"""
RESET_PASSWORD_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">

    <title>SugarCoated Security | Reset Password</title>

    <style>
        * {
            box-sizing: border-box;
        }

        body {
            min-height: 100vh;
            margin: 0;
            display: flex;
            align-items: center;
            justify-content: center;
            background: radial-gradient(
                circle at top,
                #10243c 0%,
                #040b16 55%
            );
            color: white;
            font-family: Arial, sans-serif;
        }

        .card {
            width: min(480px, 92%);
            padding: 35px;
            background: rgba(10,25,44,.96);
            border: 1px solid rgba(99,179,255,.35);
            border-radius: 18px;
        }

        h1 {
            margin-top: 0;
        }

        .subtitle {
            color: #8fa6bd;
            margin-bottom: 25px;
        }

        label {
            display: block;
            margin: 16px 0 7px;
            color: #b9d5ed;
        }

        input {
            width: 100%;
            padding: 13px;
            border-radius: 9px;
            border: 1px solid #24435f;
            background: #071524;
            color: white;
        }

        button {
            width: 100%;
            margin-top: 24px;
            padding: 13px;
            border: 0;
            border-radius: 9px;
            background: linear-gradient(
                90deg,
                #20bfff,
                #7067ff
            );
            color: white;
            font-weight: bold;
            cursor: pointer;
        }

        .message {
            padding: 12px;
            margin-bottom: 15px;
            border-radius: 8px;
        }

        .error {
            background: rgba(255,94,104,.12);
            color: #ff858d;
        }

        .success {
            background: rgba(105,230,166,.12);
            color: #69e6a6;
        }

        .back {
            display: block;
            margin-top: 20px;
            text-align: center;
            color: #63b3ff;
            text-decoration: none;
        }
    </style>
</head>

<body>

<form class="card" method="POST">

    <input
        type="hidden"
        name="csrf_token"
        value="{{ csrf_token() }}"
    >

    <h1>Create New Password</h1>

    <div class="subtitle">
        Enter a new password for your SugarCoated Security account.
    </div>

    {% if error %}
        <div class="message error">
            {{ error }}
        </div>
    {% endif %}

    {% if success %}
        <div class="message success">
            {{ success }}
        </div>
    {% endif %}

    {% if not success %}

        <label>New Password</label>

        <input
            type="password"
            name="new_password"
            minlength="12"
            autocomplete="new-password"
            required
        >

        <label>Confirm New Password</label>

        <input
            type="password"
            name="confirm_password"
            minlength="12"
            autocomplete="new-password"
            required
        >

        <button type="submit">
            Reset Password
        </button>

    {% endif %}

    <a class="back" href="{{ url_for('login') }}">
        ← Return to Login
    </a>

</form>

</body>
</html>
"""


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    error = None
    success = None

    if request.method == "POST":
        require_csrf()

        new_password = request.form.get(
            "new_password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        if len(new_password) < 12:
            error = "Password must be at least 12 characters."

        elif new_password != confirm_password:
            error = "Passwords do not match."

        else:
            changed = reset_password_with_token(
                app.config["USER_DB"],
                token,
                new_password
            )

            if changed:
                success = (
                    "Password reset successfully. "
                    "You can now return to login."
                )
            else:
                error = (
                    "This password reset link is invalid or has expired."
                )

    return render_template_string(
        RESET_PASSWORD_PAGE,
        error=error,
        success=success
    )
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None

    if request.method == "POST":
        require_csrf()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        user = get_user_by_email(
            app.config["USER_DB"],
            email
        )

        if user:
            reset_token = secrets.token_urlsafe(32)

            reset_expires = (
                datetime.now()
                + timedelta(minutes=15)
            )

            save_reset_token(
                app.config["USER_DB"],
                user["id"],
                reset_token,
                reset_expires
            )

            reset_url = url_for(
                "reset_password",
                token=reset_token,
                _external=True
            )

            try:
                send_password_reset_email(
                    user["email"],
                    reset_url
                )

            except Exception as exc:
                app.logger.error(
                    "Password reset email failed: %s",
                    exc
                )

        message = (
            "If an account exists for that email address, "
            "a password reset link has been sent."
        )

    return render_template_string(
        FORGOT_PASSWORD_PAGE,
        message=message
    )
@app.route("/logout", methods=["POST"])
def logout():
    require_csrf()
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# DASHBOARD ROUTE
# ============================================================
@app.route("/export-activity")
def export_activity():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    log_batch = (
        load_live_data(app)
        if app.config["DATA_MODE"] == "live"
        else load_event_log(LOG_FILE)
    )
    events = log_batch["events"]

    event_filter = request.args.get("event_type", "")
    source_filter = request.args.get("source_ip", "")
    search_term = request.args.get("q", "").strip()[:120].casefold()

    matching = [
        event for event in reversed(events)
        if (not event_filter or event.get("eventid") == event_filter)
        and (not source_filter or event.get("src_ip") == source_filter)
        and (
            not search_term
            or any(
                search_term in str(event.get(key) or "").casefold()
                for key in (
                    "eventid", "src_ip", "username",
                    "input", "timestamp", "session"
                )
            )
        )
    ]

    output = make_response("")
    output.headers["Content-Type"] = "text/csv; charset=utf-8"
    output.headers["Content-Disposition"] = (
        'attachment; filename="security_activity_report.csv"'
    )

    import io
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "Timestamp", "Event Type", "Source IP",
        "Username", "Details"
    ])

    for event in matching:
        writer.writerow([
            event.get("timestamp", ""),
            event.get("eventid", ""),
            event.get("src_ip", ""),
            event.get("username", ""),
            event.get("input", "")
        ])

    output.set_data(buffer.getvalue())
    return output
@app.route("/")
@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    log_batch = load_live_data(app) if app.config["DATA_MODE"] == "live" else load_event_log(LOG_FILE)
    events = log_batch["events"]
    analysis = analyze_events(events)
    brute_force_alerts = detect_brute_force(events)

        # SYSTEM HEALTH MONITORING
    live_mode = app.config["DATA_MODE"] == "live"

    if not live_mode:
        system_health = {
            "status": "Demo Mode",
            "detail": "Displaying sample events, not live Cowrie activity.",
            "last_upload": None,
            "data_source": "Sample Data",
        }
    elif not log_batch.get("received_at"):
        system_health = {
            "status": "Waiting for Data",
            "detail": "No live event snapshot has been received.",
            "last_upload": None,
            "data_source": "Live Upload API",
        }
    elif log_batch.get("stale"):
        system_health = {
            "status": "Updates Delayed",
            "detail": "The most recent snapshot is over 3 minutes old.",
            "last_upload": log_batch["received_at"],
            "data_source": "Live Upload API",
        }
    else:
        system_health = {
            "status": "Receiving Events",
            "detail": "A recent event snapshot was received.",
            "last_upload": log_batch["received_at"],
            "data_source": "Live Upload API",
        }

    # --------------------------------------------------------
    # BASIC COUNTERS
    # --------------------------------------------------------

    total_events = len(events)

    commands = sum(
        1 for e in events
        if e.get("eventid") == "cowrie.command.input"
    )

    logins = sum(
        1 for e in events
        if e.get("eventid") in (
            "cowrie.login.success",
            "cowrie.login.failed"
        )
    )

    ip_counter = Counter(
        e.get("src_ip")
        for e in events
        if e.get("src_ip")
    )

    command_counter = Counter(
        e.get("input")
        for e in events
        if e.get("eventid") == "cowrie.command.input"
        and e.get("input")
    )

    login_events = [
        e for e in events
        if e.get("eventid") in (
            "cowrie.login.success",
            "cowrie.login.failed"
        )
    ]

    # --------------------------------------------------------
    # RECENT EVENTS
    # --------------------------------------------------------

    event_filter = request.args.get("event_type", "")
    source_filter = request.args.get("source_ip", "")
    search_query = request.args.get("q", "").strip()[:120]
    search_term = search_query.casefold()
    show_all = request.args.get("view") == "all" or bool(event_filter or source_filter or search_term)

    matching = [
    event for event in reversed(events)
    if (not event_filter or event["eventid"] == event_filter)
    and (not source_filter or event["src_ip"] == source_filter)
    and (
        not search_term
        or any(
            search_term in str(event.get(key) or "").casefold()
            for key in ("eventid", "src_ip", "username", "input", "timestamp", "session")
        )
    )
]

    page_size = 25 if show_all else 10
    page_count = max(1, (len(matching) + page_size - 1) // page_size)

    page = (
        min(max(request.args.get("page", 1, type=int), 1), page_count)
        if show_all else 1
    )

    start = (page - 1) * page_size

    activity = {
        "events": matching[start:start + page_size],
        "count": len(matching),
        "show_all": show_all,
        "page": page,
        "pages": page_count,
        "first": start + 1 if matching else 0,
        "last": min(start + page_size, len(matching)),
        "event_filter": event_filter,
        "source_filter": source_filter,
        "search_query": search_query,
        "event_options": sorted(
            {event["eventid"] for event in events}
            | ({event_filter} if event_filter else set())
        ),
        "source_options": sorted(
            {event["src_ip"] for event in events if event["src_ip"]}
            | ({source_filter} if source_filter else set())
        ),
    }

    def activity_url(page=1):
        return url_for(
            "dashboard",
            view="all",
            page=page,
            event_type=event_filter,
            source_ip=source_filter,
            _anchor="activity"
        )

    activity.update(
        all_url=activity_url(),
        previous_url=activity_url(max(1, page - 1)),
        next_url=activity_url(min(page_count, page + 1))
    )

    max_ip_count = max(
        [count for _, count in ip_counter.most_common(10)],
        default=1
    )

    max_command_count = max(
        [count for _, count in command_counter.most_common(10)],
        default=1
    )

    # --------------------------------------------------------
    # MAP DATA
    # --------------------------------------------------------

    attacker_locations = []

    demo_coordinates = {
        "185.220.101.5": {
            "lat": 51.1657,
            "lon": 10.4515,
            "country": "Germany"
        },
        "103.27.186.12": {
            "lat": 23.6850,
            "lon": 90.3563,
            "country": "Bangladesh"
        },
        "127.0.0.1": {
            "lat": 33.7490,
            "lon": -84.3880,
            "country": "Atlanta, USA"
        }
    }

    for ip, count in ip_counter.items():
        if ip in demo_coordinates:
            location = demo_coordinates[ip]

            attacker_locations.append({
                "ip": ip,
                "events": count,
                "lat": location["lat"],
                "lng": location["lon"],
                "location": location["country"]
            })

    # --------------------------------------------------------
    # EVENT CHART
    # --------------------------------------------------------

    event_counter = Counter(
        e.get("eventid", "unknown")
        for e in events
    )

    event_labels = list(event_counter.keys())
    event_values = list(event_counter.values())

    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template_string(
        HTML,
        total_events=total_events,

        commands=commands,

        logins=logins,

        analysis=analysis,
        system_health=system_health,
        brute_force_alerts=brute_force_alerts,
        log_batch=log_batch,
        live_mode=app.config["DATA_MODE"] == "live",
        is_sample_data=app.config["DATA_MODE"] == "sample" and Path(LOG_FILE).resolve() == (Path(__file__).resolve().parents[1] / "sample_data" / "cowrie.json"),

        source_ips=
            ip_counter.most_common(10),

        commands_list=
            command_counter.most_common(10),

        login_events=
            login_events[-10:],

        activity=activity,
        event_labels_map=EVENT_LABELS,

        max_ip_count=
            max_ip_count,

        max_command_count=
            max_command_count,

        attacker_locations=
            attacker_locations,

        event_labels=
            event_labels,

        event_values=
            event_values,

        current_time=
            current_time

    )


# ============================================================
# RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(

        host="0.0.0.0",

        port=int(
            os.environ.get(
                "PORT",
                5050
            )
        ),

        debug=True

    )
