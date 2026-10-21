from functools import lru_cache
"""Analyze Cowrie events without executing commands or fetching remote content.

The dashboard/live-data integration should call analyze_events(real_event_records).
load_event_log() is a local-file fallback for testing or offline use.
Rule-based risk scores are heuristics, not probabilities of attack.
"""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
from pathlib import Path
import shlex

DEFAULT_LOG = Path(__file__).resolve().parents[1] / "sample_data" / "cowrie.json"
FIELDS = ("eventid", "src_ip", "timestamp", "input", "username", "session")
SEVERITY = {"Unknown": -1, "Low": 0, "Medium": 1, "High": 2}

# Kept only for backwards compatibility with the existing dashboard.
# These are synthetic examples, not real labeled training data.
TRAINING_X = [[0, 0], [1, 1], [2, 1], [3, 1], [4, 1], [8, 3], [10, 4], [15, 5]]
TRAINING_Y = [0, 0, 0, 0, 0, 1, 1, 1]
MODEL_LIMITATION = (
    "The Random Forest is a demonstration model trained on eight made-up examples "
    "using only command and login counts. Its output is not an attack probability and "
    "has not been validated on real labeled traffic. Use the rule-based evidence and "
    "risk score as transparent triage aids, not proof of compromise."
)


def normalize_event(event):
    """Return a safe, normalized Cowrie event, or None for malformed records."""
    if (
        not isinstance(event, dict)
        or not isinstance(event.get("eventid"), str)
        or not event["eventid"].strip()
    ):
        return None
    if any(event.get(key) is not None and not isinstance(event.get(key), str) for key in FIELDS):
        return None
    return {key: event.get(key) or "" for key in FIELDS}


def load_event_log(path=DEFAULT_LOG):
    """Load newline-delimited Cowrie JSON from a file; this is not the live connector."""
    batch = {"events": [], "skipped": 0, "error": None}
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if not line.strip():
                    continue
                try:
                    event = normalize_event(json.loads(line))
                except (ValueError, RecursionError):
                    event = None
                if event is None:
                    batch["skipped"] += 1
                else:
                    batch["events"].append(event)
    except OSError:
        batch["error"] = "The event log is unavailable. Check the configured path and read access."
    return batch


@lru_cache(maxsize=1)
def get_model():
    from sklearn.ensemble import RandomForestClassifier
    return RandomForestClassifier(n_estimators=100, random_state=42).fit(TRAINING_X, TRAINING_Y)


def model_signal(commands, logins):
    """Legacy demonstration signal; never interpret as calibrated probability."""
    result = {
        "available": False,
        "label": "Not evaluated",
        "suspicious_signal": None,
        "training_examples": len(TRAINING_X),
        "limitation": MODEL_LIMITATION,
        "features": {"commands": commands, "logins": logins},
        "model_type": "synthetic demonstration Random Forest",
    }
    if not commands and not logins:
        return result
    try:
        from sklearn.ensemble import RandomForestClassifier
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(TRAINING_X, TRAINING_Y)
        probabilities = model.predict_proba([[commands, logins]])[0]
        signal = float(probabilities[list(model.classes_).index(1)])
        result.update(
            available=True,
            suspicious_signal=round(signal * 100),
            label="Suspicious pattern" if signal > 0.5 else "Lower activity pattern",
        )
    except (ImportError, ValueError):
        result["label"] = "Model unavailable"
    return result


def command_indicators(text):
    """Inspect shell command strings without executing them."""
    statements, buffer = [], []
    quote, escaped, comment = None, False, False
    for character in text:
        if comment:
            if character == "\n":
                comment = False
                statements.append("".join(buffer))
                buffer = []
            continue
        if escaped:
            buffer.append(character)
            escaped = False
            continue
        if character == "\\" and quote != "'":
            buffer.append(character)
            escaped = True
        elif quote:
            buffer.append(character)
            if character == quote:
                quote = None
        elif character in {"'", '"'}:
            quote = character
            buffer.append(character)
        elif character == "#" and (not buffer or buffer[-1].isspace()):
            comment = True
        elif character in ";&|\n":
            statements.append("".join(buffer))
            buffer = []
        else:
            buffer.append(character)
    statements.append("".join(buffer))

    segments = []
    for statement in statements:
        try:
            segments.append(shlex.split(statement))
        except ValueError:
            continue

    indicators = set()
    for words in segments:
        if words and words[0] == "sudo":
            words = words[1:]
            while words and words[0].startswith("-"):
                words = words[1:]
        if not words:
            continue
        program = words[0].rsplit("/", 1)[-1]
        args = words[1:]

        if program in {"wget", "curl"} and any(
            word.startswith(("http://", "https://", "ftp://")) for word in args
        ):
            indicators.add("download")
        if program in {"cat", "head", "tail", "less", "more", "grep", "awk", "sed"} and any(
            word in {"/etc/passwd", "/etc/shadow"} for word in args
        ):
            indicators.add("account-files")
        if program in {"tee", "cp", "mv", "install", "touch"} and any(
            "authorized_keys" in word for word in args
        ):
            indicators.add("ssh-keys")
        if program == "crontab" and any(
            word in {"-e", "-r"} or word.startswith("-e") for word in args
        ):
            indicators.add("cron-change")
        if program == "rm" and any(
            word.startswith("-") and "r" in word and "f" in word for word in args
        ):
            indicators.add("recursive-delete")
        if program in {"whoami", "id", "uname", "pwd", "ls"}:
            indicators.add("recon")
    return indicators


RULES = {
    "ssh-keys": ("High", "Attempted SSH key modification",
        "A command referenced an authorized-keys file in a write-oriented operation. The record does not establish that the change succeeded.",
        "Review the full command and subsequent activity; verify SSH access controls on authorized systems."),
    "cron-change": ("Medium", "Attempted scheduled-task change",
        "A command attempted to edit or remove a crontab. This can be legitimate administration or persistence activity.",
        "Review the user's commands and the system's scheduled-task records."),
    "recursive-delete": ("High", "Potentially destructive removal",
        "A command used a recursive, forced remove option. The target and outcome must be reviewed.",
        "Examine the command arguments and related activity without running them."),
    "download": ("High", "Attempted file download",
        "A command attempted to download a file. The event alone does not show whether it succeeded.",
        "Review the full activity record and destination. Do not open or run the file."),
    "account-files": ("High", "Attempted to read account details",
        "A command referenced an account file. The event alone does not show whether the read succeeded.",
        "Review the command output and subsequent activity in the isolated test environment."),
    "failed-logins": ("Medium", "Repeated login failures",
        "The same source IP has at least three failed login attempts in the analyzed records.",
        "Review usernames and timestamps; compare related records before deciding whether to block the address."),
    "successful-login": ("Medium", "Login accepted by the honeypot",
        "The honeypot accepted a login. This does not mean a real account was accessed.",
        "Review activity after login and confirm the honeypot is isolated from real systems."),
    "recon": ("Low", "Basic system discovery",
        "Commands checked usernames, directories, or system information. These can also be normal actions.",
        "Compare these commands with other evidence before deciding whether the activity is suspicious."),
}


def _score_findings(findings, failed_logins=0, commands=0, event_count=0):
    """Explainable heuristic score from observed evidence; not an ML probability."""
    points_by_severity = {"High": 35, "Medium": 20, "Low": 8}
    # Count each distinct rule once so repeated copies of one rule cannot inflate score.
    unique = {(item["id"], item["severity"]) for item in findings}
    score = sum(points_by_severity.get(severity, 0) for _, severity in unique)
    reasons = [item["title"] for item in findings if (item["id"], item["severity"]) in unique]

    # Small bounded additions for volume, with explicit evidence labels.
    if failed_logins >= 5:
        score += 10
        reasons.append("5 or more failed login records")
    if commands >= 10:
        score += 5
        reasons.append("10 or more command records")
    score = min(score, 100)

    if not event_count:
        level = "Unknown"
    elif score >= 60:
        level = "High"
    elif score >= 25:
        level = "Medium"
    elif score > 0:
        level = "Low"
    else:
        level = "No indicators detected"

    return {
        "score": score,
        "level": level,
        "reasons": list(dict.fromkeys(reasons)),
        "method": "Heuristic evidence score (0-100), not probability of attack",
    }


def analyze_events(events):
    """Analyze event records supplied by the caller, including real live-event records."""
    valid = [clean for event in events if (clean := normalize_event(event)) is not None]
    command_events = [event for event in valid if event["eventid"] == "cowrie.command.input"]
    login_events = [
        event for event in valid
        if event["eventid"] in {"cowrie.login.failed", "cowrie.login.success"}
    ]
    command_count = len(command_events)
    login_count = len(login_events)
    model = model_signal(command_count, login_count)

    source_events = defaultdict(list)
    event_matches = defaultdict(list)
    timestamps = []

    for event in valid:
        ip = event["src_ip"] or "Unknown"
        source_events[ip].append(event)

        if event["timestamp"]:
            try:
                stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                timestamps.append(
                    stamp.replace(tzinfo=timezone.utc)
                    if stamp.tzinfo is None else stamp.astimezone(timezone.utc)
                )
            except (ValueError, OverflowError):
                pass

        if event["eventid"] == "cowrie.command.input":
            for rule in command_indicators(event["input"]):
                event_matches[rule].append(event)
        elif event["eventid"] == "cowrie.login.success":
            event_matches["successful-login"].append(event)

    for ip, rows in source_events.items():
        failed = [event for event in rows if event["eventid"] == "cowrie.login.failed"]
        if ip != "Unknown" and len(failed) >= 3:
            event_matches["failed-logins"].extend(failed)

    findings = []
    source_findings = defaultdict(list)
    for rule, (severity, title, description, recommendation) in RULES.items():
        rows = event_matches[rule]
        if not rows:
            continue
        ips = sorted({event["src_ip"] or "Unknown" for event in rows})
        evidence = [
            {
                "ip": event["src_ip"] or "Unknown",
                "timestamp": event["timestamp"] or "Time unavailable",
                "detail": (
                    event["input"]
                    or f'{event["eventid"]} · user: {event["username"] or "not recorded"}'
                )[:400],
            }
            for event in rows[:3]
        ]
        finding = {
            "id": rule, "severity": severity, "title": title,
            "description": description, "recommendation": recommendation,
            "count": len(rows), "evidence": evidence, "source_ips": ips,
        }
        findings.append(finding)
        for ip in ips:
            source_findings[ip].append(finding)

    sources = []
    for ip, rows in source_events.items():
        counts = Counter(event["eventid"] for event in rows)
        source_rule_findings = source_findings[ip]
        failed_count = counts["cowrie.login.failed"]
        command_total = counts["cowrie.command.input"]
        score = _score_findings(
            source_rule_findings,
            failed_logins=failed_count,
            commands=command_total,
            event_count=len(rows),
        )
        severity = score["level"]
        if severity == "No indicators detected":
            severity = "Low"
        sources.append({
            "ip": ip,
            "event_count": len(rows),
            "commands": command_total,
            "failed_logins": failed_count,
            "successful_logins": counts["cowrie.login.success"],
            "severity": severity,
            "risk_score": score["score"],
            "risk_level": score["level"],
            "risk_reasons": score["reasons"],
            "findings": [item["title"] for item in source_rule_findings],
        })
    sources.sort(
        key=lambda row: (
            -row["risk_score"], -row["event_count"], row["ip"]
        )
    )

    overall_score = _score_findings(
        findings,
        failed_logins=sum(event["eventid"] == "cowrie.login.failed" for event in valid),
        commands=command_count,
        event_count=len(valid),
    )
    if not valid:
        status, priority = "NO DATA", "Unknown"
        summary = "No usable events are available. Connect or load Cowrie event records to begin analysis."
    elif not command_count and not login_count:
        status, priority = "LIMITED DATA", "Unknown"
        summary = "Events are present, but no command or login activity is available for this analysis."
    elif any(item["severity"] == "High" for item in findings):
        status, priority = "SUSPICIOUS", "High"
        summary = "Recorded actions need closer review. Evidence does not by itself prove a compromise."
    elif any(item["severity"] == "Medium" for item in findings) or overall_score["score"] >= 25:
        status, priority = "REVIEW", "Medium"
        summary = "Some activity needs review. Check recorded actions before deciding what happened."
    else:
        status = "NO INDICATORS" if not findings else "OBSERVED"
        priority = "Low" if findings else "Low"
        summary = "No high-priority rule indicators were detected. This does not guarantee activity is safe."

    return {
        "status": status,
        "priority": priority,
        "summary": summary,
        "event_count": len(valid),
        "command_count": command_count,
        "login_count": login_count,
        "source_count": len(sources),
        "findings": findings,
        "sources": sources[:10],
        "model": model,
        "risk_score": overall_score["score"],
        "risk_level": overall_score["level"],
        "risk_reasons": overall_score["reasons"],
        "risk_method": overall_score["method"],
        "first_event": min(timestamps).strftime("%d %b %Y, %H:%M UTC") if timestamps else None,
        "last_event": max(timestamps).strftime("%d %b %Y, %H:%M UTC") if timestamps else None,
    }


def detect_brute_force(events, threshold=5, window_seconds=300):
    """Detect repeated failed logins from one IP within a time window."""
    from collections import defaultdict
    from datetime import datetime, timezone, timedelta

    attempts = defaultdict(list)
    alerts = []

    for event in events:
        clean = normalize_event(event)
        if not clean or clean["eventid"] != "cowrie.login.failed":
            continue
        if not clean["src_ip"] or not clean["timestamp"]:
            continue

        try:
            timestamp = datetime.fromisoformat(
                clean["timestamp"].replace("Z", "+00:00")
            )
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            else:
                timestamp = timestamp.astimezone(timezone.utc)
        except (ValueError, OverflowError):
            continue

        attempts[clean["src_ip"]].append((timestamp, clean))

    for ip, rows in attempts.items():
        rows.sort(key=lambda row: row[0])
        left = 0

        for right, (timestamp, event) in enumerate(rows):
            while (timestamp - rows[left][0]).total_seconds() > window_seconds:
                left += 1

            if right - left + 1 >= threshold:
                alerts.append({
                    "ip": ip,
                    "count": right - left + 1,
                    "first_attempt": rows[left][1]["timestamp"],
                    "last_attempt": event["timestamp"],
                    "severity": "High",
                    "message": (
                        f"{right - left + 1} failed login attempts "
                        f"from {ip} within {window_seconds // 60} minutes"
                    ),
                })
                break

    return alerts
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path, default=DEFAULT_LOG)
    args = parser.parse_args()
    batch = load_event_log(args.log)
    result = analyze_events(batch["events"])
    result["data_quality"] = {key: batch[key] for key in ("skipped", "error")}
    result["input_source"] = "local file; not a live connection"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
