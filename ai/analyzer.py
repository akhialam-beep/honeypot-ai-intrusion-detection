import json
from collections import Counter

LOG_FILE = "../logs/cowrie.json"

events = []

with open(LOG_FILE, "r") as file:
    for line in file:
        line = line.strip()

        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

print("================================")
print("   HONEYPOT LOG ANALYZER")
print("================================")

print(f"\nTotal events: {len(events)}")

event_types = Counter(
    event.get("eventid", "unknown")
    for event in events
)

print("\nEvent Types:")
for event_type, count in event_types.items():
    print(f"  {event_type}: {count}")

commands = [
    event.get("input")
    for event in events
    if event.get("eventid") == "cowrie.command.input"
]

print(f"\nCommands recorded: {len(commands)}")

for command in commands:
    print(f"  - {command}")

login_attempts = [
    event for event in events
    if event.get("eventid") == "cowrie.login.success"
    or event.get("eventid") == "cowrie.login.failed"
]

print(f"\nLogin events: {len(login_attempts)}")

for login in login_attempts:
    print(
        f"  Username: {login.get('username', 'N/A')} | "
        f"Source IP: {login.get('src_ip', 'N/A')} | "
        f"Event: {login.get('eventid', 'N/A')}"
    )
# ==============================
# SIMPLE AI CLASSIFICATION TEST
# ==============================

from sklearn.ensemble import RandomForestClassifier

# Training examples:
# [number of commands, login attempts]
X = [
    [0, 0],
    [1, 1],
    [2, 1],
    [3, 1],
    [4, 1],
    [8, 3],
    [10, 4],
    [15, 5]
]

# 0 = normal activity
# 1 = suspicious activity
y = [
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    1
]

# Create and train the AI model
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)

# Count commands recorded by Cowrie
command_count = sum(
    1 for event in events
    if event.get("eventid") == "cowrie.command.input"
)

# Count login attempts
login_count = sum(
    1 for event in events
    if event.get("eventid") == "cowrie.login.success"
    or event.get("eventid") == "cowrie.login.failed"
)

# Ask the AI model to classify the activity
prediction = model.predict(
    [[command_count, login_count]]
)[0]

print()
print("==============================")
print("AI INTRUSION DETECTION RESULT")
print("==============================")
print("Commands detected:", command_count)
print("Login attempts:", login_count)

if prediction == 1:
    print("AI Classification: SUSPICIOUS")
else:
    print("AI Classification: NORMAL")
