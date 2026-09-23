"""Local Cowrie analysis. Log content is data and is never executed."""

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import lru_cache
import json
from pathlib import Path
import shlex


DEFAULT_LOG = Path(__file__).resolve().parents[1] / "sample_data" / "cowrie.json"
FIELDS = ("eventid", "src_ip", "timestamp", "input", "username", "session")
SEVERITY = {"Unknown": -1, "Low": 0, "Medium": 1, "High": 2}
TRAINING_X = [[0, 0], [1, 1], [2, 1], [3, 1], [4, 1], [8, 3], [10, 4], [15, 5]]
TRAINING_Y = [0, 0, 0, 0, 0, 1, 1, 1]
MODEL_LIMITATION = (
    "Demonstration model trained on eight synthetic examples, using command and login counts only. "
    "Its signal is not validated accuracy or a calibrated probability of an attack. "
    "Evidence rules are evaluated separately; neither result proves a compromise."
)


def normalize_event(event):
    if not isinstance(event, dict) or not isinstance(event.get("eventid"), str) or not event["eventid"].strip():
        return None
    if any(event.get(key) is not None and not isinstance(event.get(key), str) for key in FIELDS):
        return None
    return {key: event.get(key) or "" for key in FIELDS}


def load_event_log(path=DEFAULT_LOG):
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
    result = {"available": False, "label": "Not evaluated", "suspicious_signal": None,
              "training_examples": len(TRAINING_X), "limitation": MODEL_LIMITATION,
              "features": {"commands": commands, "logins": logins}}
    if not commands and not logins:
        return result
    try:
        model = get_model()
        probabilities = model.predict_proba([[commands, logins]])[0]
        signal = float(probabilities[list(model.classes_).index(1)])
        result.update(available=True, suspicious_signal=round(signal * 100),
                      label="Suspicious pattern" if signal > 0.5 else "Lower activity pattern")
    except (ImportError, ValueError):
        result["label"] = "Model unavailable"
    return result


def command_indicators(text):
    """Inspect basic shell commands without executing or fetching any content."""
    # Split only real shell delimiters; shlex's unquoted output loses that distinction.
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
        elif character in {"'", '\"'}:
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
        if program in {"wget", "curl"} and any(word.startswith(("http://", "https://", "ftp://")) for word in words[1:]):
            indicators.add("download")
        if program in {"cat", "head", "tail", "less", "more", "grep", "awk", "sed"} and any(word in {"/etc/passwd", "/etc/shadow"} for word in words[1:]):
            indicators.add("account-files")
        if program in {"whoami", "id", "uname", "pwd", "ls"}:
            indicators.add("recon")
    return indicators


RULES = {
    "download": ("High", "Remote download command", "A command attempts to retrieve content from a remote address. The log does not establish that the download succeeded.", "Review the session and destination in your approved investigation tools. Preserve any captured artifact without opening or running it."),
    "account-files": ("High", "Account-file access command", "A command targets a local account file. This can indicate account discovery; the command alone does not establish that data was read.", "Inspect the session transcript for command output and follow-on activity. Verify that the honeypot remains isolated from production systems."),
    "failed-logins": ("Medium", "Repeated failed logins", "At least three failed logins share a source IP within the loaded log. This is repeated activity, not a measured attack rate.", "Review usernames and timestamps for this source. Correlate with other authentication logs before considering access-control changes."),
    "successful-login": ("Medium", "Honeypot login accepted", "The honeypot recorded an accepted login. This refers to the decoy service and does not prove access to a production account.", "Review commands in the accepted session and confirm the decoy is separated from real accounts and services."),
    "recon": ("Low", "System discovery commands", "Commands inspect identity, directories or system information. These commands can also be part of ordinary administration.", "Review these commands alongside download, account-access and login evidence before assigning intent."),
}


def analyze_events(events):
    valid = [clean for event in events if (clean := normalize_event(event)) is not None]
    command_count = sum(event["eventid"] == "cowrie.command.input" for event in valid)
    login_count = sum(event["eventid"] in {"cowrie.login.failed", "cowrie.login.success"} for event in valid)
    model = model_signal(command_count, login_count)
    source_events = defaultdict(list)
    matches = defaultdict(list)
    timestamps = []
    for event in valid:
        source_events[event["src_ip"] or "Unknown"].append(event)
        if event["timestamp"]:
            try:
                stamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                timestamps.append(stamp.replace(tzinfo=timezone.utc) if stamp.tzinfo is None else stamp.astimezone(timezone.utc))
            except (ValueError, OverflowError):
                pass
        if event["eventid"] == "cowrie.command.input":
            for rule in command_indicators(event["input"]):
                matches[rule].append(event)
        elif event["eventid"] == "cowrie.login.success":
            matches["successful-login"].append(event)
    for ip, rows in source_events.items():
        failed = [event for event in rows if event["eventid"] == "cowrie.login.failed"]
        if ip != "Unknown" and len(failed) >= 3:
            matches["failed-logins"].extend(failed)

    findings = []
    source_findings = defaultdict(list)
    for rule, (severity, title, description, recommendation) in RULES.items():
        rows = matches[rule]
        if not rows:
            continue
        ips = sorted({event["src_ip"] or "Unknown" for event in rows})
        evidence = [{"ip": event["src_ip"] or "Unknown", "timestamp": event["timestamp"] or "Time unavailable",
                     "detail": (event["input"] or f'{event["eventid"]} · user: {event["username"] or "not recorded"}')[:400]}
                    for event in rows[:3]]
        findings.append({"id": rule, "severity": severity, "title": title, "description": description,
                         "recommendation": recommendation, "count": len(rows), "evidence": evidence, "source_ips": ips})
        for ip in ips:
            source_findings[ip].append({"title": title, "severity": severity})

    priority = max((item["severity"] for item in findings), key=SEVERITY.get, default="Low")
    if not valid:
        status, priority = "NO DATA", "Unknown"
        summary = "No usable events are available. Load Cowrie activity to begin an assessment."
    elif not command_count and not login_count:
        status, priority = "LIMITED DATA", "Unknown"
        summary = "Events are present, but no command or login activity is available for this analysis."
    elif priority == "High":
        status = "SUSPICIOUS"
        summary = "High-priority command indicators need review. Inspect the evidence and session context before drawing conclusions about intent or impact."
    elif priority == "Medium" or (model["suspicious_signal"] or 0) > 50:
        status, priority = "REVIEW", "Medium"
        summary = "Activity merits a closer look. Review the observed patterns and the demonstration model signal together."
    else:
        status = "NO INDICATORS" if not findings else "OBSERVED"
        summary = "No high-priority indicators were found by the current checks. This does not establish that the activity is safe."

    sources = []
    for ip, rows in source_events.items():
        counts = Counter(event["eventid"] for event in rows)
        relevant = source_findings[ip]
        severity = max((item["severity"] for item in relevant), key=SEVERITY.get, default="Unknown")
        sources.append({"ip": ip, "event_count": len(rows), "commands": counts["cowrie.command.input"],
                        "failed_logins": counts["cowrie.login.failed"], "successful_logins": counts["cowrie.login.success"],
                        "severity": severity, "findings": [item["title"] for item in relevant]})
    sources.sort(key=lambda row: (-SEVERITY[row["severity"]], -row["event_count"], row["ip"]))
    return {"status": status, "priority": priority, "summary": summary, "event_count": len(valid),
            "command_count": command_count, "login_count": login_count, "source_count": len(sources),
            "findings": findings, "sources": sources[:10], "model": model,
            "first_event": min(timestamps).strftime("%d %b %Y, %H:%M UTC") if timestamps else None,
            "last_event": max(timestamps).strftime("%d %b %Y, %H:%M UTC") if timestamps else None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", nargs="?", type=Path, default=DEFAULT_LOG)
    args = parser.parse_args()
    batch = load_event_log(args.log)
    result = analyze_events(batch["events"])
    result["data_quality"] = {key: batch[key] for key in ("skipped", "error")}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
