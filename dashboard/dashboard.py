from flask import Flask, render_template_string
import json
import os
from collections import Counter

app = Flask(__name__)

LOG_FILE = os.path.expanduser("~/honeypot-project/logs/cowrie.json")


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


HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Honeypot AI Intrusion Detection</title>

    <meta name="viewport" content="width=device-width, initial-scale=1">

    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            background: #f4f6f8;
            color: #222;
        }

        header {
            background: #111827;
            color: white;
            padding: 25px;
        }

        header h1 {
            margin: 0;
        }

        header p {
            margin-bottom: 0;
            color: #cbd5e1;
        }

        .container {
            max-width: 1200px;
            margin: 30px auto;
            padding: 0 20px;
        }

        .cards {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background: white;
            padding: 22px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .card h3 {
            margin-top: 0;
            color: #64748b;
        }

        .number {
            font-size: 32px;
            font-weight: bold;
        }

        .section {
            background: white;
            padding: 25px;
            border-radius: 12px;
            margin-bottom: 25px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        table {
            width: 100%;
            border-collapse: collapse;
        }

        th, td {
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
            text-align: left;
        }

        th {
            background: #f8fafc;
        }

        .normal {
            color: #15803d;
            font-weight: bold;
        }

        .alert {
            color: #dc2626;
            font-weight: bold;
        }

        .badge {
            background: #e2e8f0;
            padding: 5px 9px;
            border-radius: 6px;
        }

        @media (max-width: 800px) {
            .cards {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 500px) {
            .cards {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>

<body>

<header>
    <h1>🐝 Honeypot AI Intrusion Detection</h1>
    <p>Real-time monitoring dashboard</p>
</header>

<div class="container">

    <div class="cards">

        <div class="card">
            <h3>Total Events</h3>
            <div class="number">{{ total_events }}</div>
        </div>

        <div class="card">
            <h3>Commands Detected</h3>
            <div class="number">{{ commands }}</div>
        </div>

        <div class="card">
            <h3>Login Attempts</h3>
            <div class="number">{{ logins }}</div>
        </div>

        <div class="card">
            <h3>AI Classification</h3>

            {% if classification == "SUSPICIOUS" %}
                <div class="number alert">🚨 {{ classification }}</div>
            {% else %}
                <div class="number normal">✅ {{ classification }}</div>
            {% endif %}

        </div>

    </div>


    <div class="section">

        <h2>🤖 AI Intrusion Detection</h2>

        <p>
            <strong>Classification:</strong>

            {% if classification == "SUSPICIOUS" %}
                <span class="alert">🚨 Suspicious Activity</span>
            {% else %}
                <span class="normal">✅ Normal Activity</span>
            {% endif %}

        </p>

        <p>
            The AI analyzer evaluates activity collected by the honeypot
            and classifies the observed activity.
        </p>

    </div>


    <div class="section">

        <h2>🌐 Source IP Addresses</h2>

        <table>

            <tr>
                <th>Source IP</th>
                <th>Events</th>
            </tr>

            {% for ip, count in source_ips %}
            <tr>
                <td>{{ ip }}</td>
                <td><span class="badge">{{ count }}</span></td>
            </tr>
            {% endfor %}

        </table>

    </div>


    <div class="section">

        <h2>💻 Commands Detected</h2>

        <table>

            <tr>
                <th>Command</th>
                <th>Count</th>
            </tr>

            {% for command, count in commands_list %}
            <tr>
                <td>{{ command }}</td>
                <td><span class="badge">{{ count }}</span></td>
            </tr>
            {% endfor %}

        </table>

    </div>


    <div class="section">

        <h2>🔐 Login Activity</h2>

        <table>

            <tr>
                <th>Username</th>
                <th>Source IP</th>
                <th>Event</th>
            </tr>

            {% for login in login_events %}

            <tr>
                <td>{{ login.username }}</td>
                <td>{{ login.ip }}</td>
                <td>{{ login.event }}</td>
            </tr>

            {% endfor %}

        </table>

    </div>


    <div class="section">

        <h2>📊 Recent Honeypot Activity</h2>

        <table>

            <tr>
                <th>Timestamp</th>
                <th>Event</th>
                <th>Source IP</th>
            </tr>

            {% for event in recent_events %}

            <tr>
                <td>{{ event.timestamp }}</td>
                <td>{{ event.event }}</td>
                <td>{{ event.ip }}</td>
            </tr>

            {% endfor %}

        </table>

    </div>

</div>

</body>
</html>
"""


@app.route("/")
def dashboard():

    events = load_events()

    total_events = len(events)

    command_events = [
        event for event in events
        if event.get("eventid") == "cowrie.command.input"
    ]

    login_events_raw = [
        event for event in events
        if event.get("eventid") in [
            "cowrie.login.success",
            "cowrie.login.failed"
        ]
    ]

    commands = len(command_events)
    logins = len(login_events_raw)

    command_counter = Counter(
        event.get("input", "Unknown")
        for event in command_events
    )

    ip_counter = Counter(
        event.get("src_ip", "Unknown")
        for event in events
        if event.get("src_ip")
    )

    login_events = []

    for event in login_events_raw:

        login_events.append({
            "username": event.get("username", "N/A"),
            "ip": event.get("src_ip", "N/A"),
            "event": event.get("eventid", "N/A")
        })

    recent_events = []

    for event in events[-10:]:

        recent_events.append({
            "timestamp": event.get("timestamp", "N/A"),
            "event": event.get("eventid", "N/A"),
            "ip": event.get("src_ip", "N/A")
        })

    # Simple first-stage classification.
    # We will replace this with the actual AI model later.

    if commands >= 5 or logins >= 3:
        classification = "SUSPICIOUS"
    else:
        classification = "NORMAL"

    return render_template_string(
        HTML,
        total_events=total_events,
        commands=commands,
        logins=logins,
        classification=classification,
        source_ips=ip_counter.most_common(),
        commands_list=command_counter.most_common(),
        login_events=login_events,
        recent_events=recent_events
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
