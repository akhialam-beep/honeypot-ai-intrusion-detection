from flask import Flask, render_template_string, request, session, redirect, url_for
import json
import os
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from collections import Counter

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

DEMO_USERNAME = os.environ.get("DEMO_USERNAME", "demo")
DEMO_PASSWORD_HASH = generate_password_hash(
    os.environ.get("DEMO_PASSWORD", "StickyDemo2026!")
)

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
    events = []

    if not os.path.exists(LOG_FILE):
        return events

    with open(LOG_FILE, "r") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))

            except json.JSONDecodeError:
                pass

    return events


# ============================================================
# HTML / CSS / JAVASCRIPT
# ============================================================

HTML = """

<!DOCTYPE html>

<html>

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
        href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
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

    background: #07111f;
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
   AI STATUS
   ============================================================ */

.ai-status {

    display: flex;

    align-items: center;

    gap: 15px;

    padding: 20px;

    border-radius: 15px;

    background:
        linear-gradient(
            135deg,
            rgba(239,68,68,0.1),
            rgba(127,29,29,0.08)
        );

    border:
        1px solid rgba(239,68,68,0.2);

    margin-bottom: 20px;
}


.ai-status-icon {

    width: 48px;

    height: 48px;

    border-radius: 14px;

    display: flex;

    align-items: center;

    justify-content: center;

    color: #f87171;

    background:
        rgba(239,68,68,0.13);

    font-size: 20px;
}


.ai-title {

    font-weight: 800;

    color: #f87171;

    font-size: 16px;
}


.ai-description {

    color: #7890a8;

    font-size: 11px;

    margin-top: 4px;
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
            Live Feed
        </a>

        <a class="nav-link" href="#analytics">
            <i class="fa-solid fa-chart-line"></i>
            Analytics
        </a>

        <a class="nav-link" href="#map-section">
            <i class="fa-solid fa-location-dot"></i>
            IP Map
        </a>

    </div>


    <div class="system-status">

        <span class="status-dot"></span>

        <div class="status-information">

            <div class="status-title">
                System Online
            </div>

            <div class="status-time">
                {{ current_time }}
            </div>

            <a href="/logout" class="logout-button">
                <i class="fa-solid fa-right-from-bracket"></i>
                Logout
            </a>

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

            Monitor. Analyze. Detect. Stay Ahead.

        </div>


        <div class="hero-description">

            This dashboard visualizes activity collected by our
            Cowrie honeypot and presents security events,
            source IP addresses, login attempts, commands,
            and AI-based threat classification.

        </div>

    </div>

</section>



<!-- ============================================================
     METRICS
     ============================================================ -->

<section class="metrics">


    <div class="metric">

        <div class="metric-icon blue">

            <i class="fa-solid fa-file-lines"></i>

        </div>

        <div class="metric-title">
            TOTAL EVENTS
        </div>

        <div class="metric-number">
            {{ total_events }}
        </div>

        <div class="metric-footer">
            Events collected by Cowrie
        </div>

        <div class="metric-line"></div>

    </div>



    <div class="metric">

        <div class="metric-icon purple">

            <i class="fa-solid fa-terminal"></i>

        </div>

        <div class="metric-title">
            COMMANDS DETECTED
        </div>

        <div class="metric-number">
            {{ commands }}
        </div>

        <div class="metric-footer">
            Commands entered by sessions
        </div>

        <div class="metric-line"></div>

    </div>



    <div class="metric">

        <div class="metric-icon green">

            <i class="fa-solid fa-user-shield"></i>

        </div>

        <div class="metric-title">
            LOGIN ATTEMPTS
        </div>

        <div class="metric-number">
            {{ logins }}
        </div>

        <div class="metric-footer">
            Authentication activity
        </div>

        <div class="metric-line"></div>

    </div>



    <div class="metric">

        <div class="metric-icon red">

            <i class="fa-solid fa-triangle-exclamation"></i>

        </div>

        <div class="metric-title">
            AI CLASSIFICATION
        </div>


        {% if classification == "SUSPICIOUS" %}

            <div
                class="metric-number"
                style="color:#f87171;"
            >

                SUSPICIOUS

            </div>

            <div class="metric-footer">

                <i class="fa-solid fa-circle-exclamation"></i>

                Potential threat detected

            </div>

        {% else %}

            <div
                class="metric-number"
                style="color:#4ade80;"
            >

                NORMAL

            </div>

            <div class="metric-footer">

                Activity within threshold

            </div>

        {% endif %}


        <div class="metric-line"></div>

    </div>


</section>



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

                    Attacker Locations

                </div>

                <div class="panel-subtitle">

                    Geographic distribution of source IP addresses

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

<div class="three-columns">


    <!-- RECENT ACTIVITY -->

    <section
        class="card-panel"
        id="activity"
    >

        <div class="panel-header">

            <div class="panel-title">

                <i class="fa-solid fa-clock-rotate-left"></i>

                Recent Activity

            </div>

            <a class="view-all" href="#activity">
                View All →
            </a>

        </div>


        <div class="table-container">

            <table>

                <thead>

                    <tr>

                        <th>Time</th>

                        <th>Event</th>

                        <th>Source IP</th>

                    </tr>

                </thead>


                <tbody>

                    {% for event in recent_events %}

                    <tr>

                        <td>
                            {{ event.timestamp }}
                        </td>

                        <td>

                            {% if "failed" in event.event %}

                                <span class="badge badge-red">
                                    {{ event.event }}
                                </span>

                            {% elif "success" in event.event %}

                                <span class="badge badge-green">
                                    {{ event.event }}
                                </span>

                            {% elif "command" in event.event %}

                                <span class="badge badge-blue">
                                    {{ event.event }}
                                </span>

                            {% else %}

                                <span class="badge badge-purple">
                                    {{ event.event }}
                                </span>

                            {% endif %}

                        </td>

                        <td class="ip">
                            {{ event.ip }}
                        </td>

                    </tr>

                    {% endfor %}

                </tbody>

            </table>

        </div>

    </section>



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
                            {{ login.ip }}
                        </td>

                        <td>

                            {% if "success" in login.event %}

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



<!-- ============================================================
     AI ANALYSIS
     ============================================================ -->

<section class="card-panel">

    <div class="panel-header">

        <div class="panel-title">

            <i class="fa-solid fa-brain"></i>

            AI Intrusion Detection

        </div>

    </div>


    <div class="ai-status">

        <div class="ai-status-icon">

            <i class="fa-solid fa-shield-virus"></i>

        </div>


        <div>

            {% if classification == "SUSPICIOUS" %}

                <div class="ai-title">
                    SUSPICIOUS ACTIVITY
                </div>

                <div class="ai-description">

                    The current activity exceeds the
                    configured detection threshold.

                </div>

            {% else %}

                <div
                    class="ai-title"
                    style="color:#4ade80;"
                >

                    NORMAL ACTIVITY

                </div>

                <div class="ai-description">

                    The current activity is within
                    the configured detection threshold.

                </div>

            {% endif %}

        </div>

    </div>


    <div
        style="
        color:#7089a1;
        font-size:12px;
        line-height:1.7;
        "
    >

        The dashboard analyzes events collected by the
        Cowrie honeypot and classifies the observed
        activity. The current prototype uses a
        first-stage rule-based classification that
        will be replaced with the project's trained
        AI model.

    </div>

</section>


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

const map = L.map("map").setView([25, 10], 2);


L.tileLayer(
    "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
    {
        attribution: "&copy; OpenStreetMap contributors",
        maxZoom: 18
    }
).addTo(map);


/*
   These coordinates are demo fallback locations.

   They allow the dashboard to show the map while your
   project is using sample_data.

   When you connect a real IP geolocation service later,
   these can be replaced with actual geolocation results.
*/

const attackerLocations = {{ attacker_locations | safe }};


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

        <div style="min-width:180px">

            <strong>
                <i class="fa-solid fa-triangle-exclamation"></i>
                Attacker Activity
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
    {{ event_labels | safe }};

const eventValues =
    {{ event_values | safe }};


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

setTimeout(function() {

    location.reload();

}, 60000);

</script>


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
        <div class="shield">🛡️</div>
        <h1>Honeypot AI</h1>
        <p class="subtitle">Secure Business Portal</p>

        {% if error %}
            <div class="error">{{ error }}</div>
        {% endif %}

        <label for="username">Username</label>
        <input id="username" name="username" required autocomplete="username">

        <label for="password">Password</label>
        <input id="password" name="password" type="password"
               required autocomplete="current-password">

        <button type="submit">Sign In</button>
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
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid_username = secrets.compare_digest(username, DEMO_USERNAME)
        valid_password = check_password_hash(DEMO_PASSWORD_HASH, password)

        if valid_username and valid_password:
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))

        error = "Incorrect username or password."

    return render_template_string(LOGIN_PAGE, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ============================================================
# DASHBOARD ROUTE
# ============================================================

@app.route("/")
@app.route("/dashboard")
def dashboard():
    if not session.get("logged_in"):
        return redirect(url_for("login"))
    events = load_events()


    # --------------------------------------------------------
    # BASIC COUNTERS
    # --------------------------------------------------------

    total_events = len(events)


    command_events = [

        event

        for event in events

        if event.get("eventid")
        == "cowrie.command.input"

    ]


    login_events_raw = [

        event

        for event in events

        if event.get("eventid")
        in [
            "cowrie.login.success",
            "cowrie.login.failed"
        ]

    ]


    commands = len(command_events)

    logins = len(login_events_raw)


    # --------------------------------------------------------
    # COMMAND COUNTER
    # --------------------------------------------------------

    command_counter = Counter(

        event.get(
            "input",
            "Unknown"
        )

        for event in command_events

    )


    # --------------------------------------------------------
    # IP COUNTER
    # --------------------------------------------------------

    ip_counter = Counter(

        event.get(
            "src_ip",
            "Unknown"
        )

        for event in events

        if event.get("src_ip")

    )


    # --------------------------------------------------------
    # LOGIN EVENTS
    # --------------------------------------------------------

    login_events = []


    for event in login_events_raw:

        login_events.append({

            "username":
                event.get(
                    "username",
                    "N/A"
                ),

            "ip":
                event.get(
                    "src_ip",
                    "N/A"
                ),

            "event":
                event.get(
                    "eventid",
                    "N/A"
                )

        })


    # --------------------------------------------------------
    # RECENT EVENTS
    # --------------------------------------------------------

    recent_events = []


    for event in reversed(events[-10:]):

        recent_events.append({

            "timestamp":
                event.get(
                    "timestamp",
                    "N/A"
                ),

            "event":
                event.get(
                    "eventid",
                    "N/A"
                ),

            "ip":
                event.get(
                    "src_ip",
                    "N/A"
                )

        })


    # --------------------------------------------------------
    # FIRST-STAGE CLASSIFICATION
    # --------------------------------------------------------

    if commands >= 5 or logins >= 3:

        classification = "SUSPICIOUS"

    else:

        classification = "NORMAL"


    # --------------------------------------------------------
    # MAP DATA
    # --------------------------------------------------------
    #
    # These are demonstration locations for the current
    # sample_data file.
    #
    # Later we can connect these IPs to a real geolocation API.
    #

    demo_coordinates = {

        "185.220.101.5": {
            "lat": 51.1657,
            "lng": 10.4515,
            "location": "Germany"
        },

        "103.27.186.12": {
            "lat": 23.6850,
            "lng": 90.3563,
            "location": "Bangladesh"
        },

        "127.0.0.1": {
            "lat": 33.7490,
            "lng": -84.3880,
            "location": "Atlanta, USA"
        }

    }


    attacker_locations = []


    for ip, count in ip_counter.items():

        if ip in demo_coordinates:

            attacker_locations.append({

                "ip": ip,

                "events": count,

                "lat":
                    demo_coordinates[ip]["lat"],

                "lng":
                    demo_coordinates[ip]["lng"],

                "location":
                    demo_coordinates[ip]["location"]

            })


    # --------------------------------------------------------
    # EVENT TYPES
    # --------------------------------------------------------

    event_counter = Counter(

        event.get(
            "eventid",
            "Unknown"
        )

        for event in events

    )


    event_labels = list(
        event_counter.keys()
    )


    event_values = list(
        event_counter.values()
    )


    # --------------------------------------------------------
    # CURRENT TIME
    # --------------------------------------------------------

    from datetime import datetime

    current_time = datetime.now().strftime(
        "%b %d, %Y %I:%M %p"
    )


    # --------------------------------------------------------
    # MAX VALUES
    # --------------------------------------------------------

    max_ip_count = (

        max(ip_counter.values())

        if ip_counter

        else 1

    )


    max_command_count = (

        max(command_counter.values())

        if command_counter

        else 1

    )


    # --------------------------------------------------------
    # RENDER
    # --------------------------------------------------------

    return render_template_string(

        HTML,

        total_events=total_events,

        commands=commands,

        logins=logins,

        classification=classification,

        source_ips=
            ip_counter.most_common(10),

        commands_list=
            command_counter.most_common(10),

        login_events=
            login_events[-10:],

        recent_events=
            recent_events,

        max_ip_count=
            max_ip_count,

        max_command_count=
            max_command_count,

        attacker_locations=
            json.dumps(attacker_locations),

        event_labels=
            json.dumps(event_labels),

        event_values=
            json.dumps(event_values),

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