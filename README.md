# Honeypot AI Intrusion Detection

A Flask dashboard for Cowrie JSON-lines events, with local analysis, source breakdowns, maps and charts.

## Run locally

Use Python 3.12 with OpenSSL/scrypt support. Apple’s bundled Python 3.9 may not support the password hashing used by the login page.

```sh
python3.12 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
python -m flask --app dashboard/dashboard.py run --host 127.0.0.1 --port 5050 --no-debugger --no-reload
```

Open http://127.0.0.1:5050 and keep the server running. The bundled demo sign-in is username `demo`, password `StickyDemo2026!`. Existing environment variables `DEMO_USERNAME`, `DEMO_PASSWORD` and `SECRET_KEY` override those defaults. For hosted use, set your own credentials and secret key, and use a production WSGI server.

## AI Analysis

Choose **AI Analysis** in the navigation, or the **View analysis** link in the overview. The section displays an overall assessment, expandable evidence, per-source priorities, recommended next steps and a separate demonstration model signal. **Refresh analysis** reads the current log again. Automatic refresh pauses while evidence is expanded or keyboard focus is inside the section.

The dashboard currently reads `sample_data/cowrie.json` and labels it as sample data. `LOG_FILE` in `dashboard/dashboard.py` selects the input. Each nonempty line should contain an object with a string `eventid`. Optional `src_ip`, `timestamp`, `input`, `username` and `session` fields must be strings or null. Invalid rows are skipped and counted. Missing files, no events and events outside the supported command/login types produce explicit limited-data states.

### Evidence checks

- Download attempts: basic `wget` or `curl` commands with HTTP, HTTPS or FTP destinations.
- Account-file commands: common file-reading tools targeting `/etc/passwd` or `/etc/shadow`.
- Repeated failures: at least three failed logins for the same known source in the loaded log, without claiming a rate or a confirmed brute-force attack.
- Accepted honeypot logins: review the decoy session; this does not establish access to production systems.
- Discovery commands: identity, system and directory inspection commands, which can also be ordinary administration.

These are limited heuristics, not a full shell interpreter or exhaustive detection coverage. Quoting, escapes and comments are respected for basic command boundaries. Commands are never executed, destinations are never fetched, and the analysis does not change firewall rules or block sources. Evidence previews show up to three matching events per finding and 400 characters per command; counts cover all usable rows. The source table shows up to ten source groups.

### Model provenance and interpretation

The Random Forest uses the project's original eight synthetic training examples and two features: command count and login count. It is fitted once per server process. The displayed suspicious-class signal is the model's class output, **not validated accuracy, calibrated attack probability or proof of compromise**. It has no held-out evaluation on real traffic. Evidence rules remain separate so a single high-priority command is visible even when the model signal is low. A signal above 50% can raise the overall status to Review; high-priority evidence sets Suspicious. Do not interpret “No indicators” as proof that activity is safe.

Analysis uses no external AI API or key. The existing website still loads fonts, map tiles and display libraries from external CDNs.

Reference: [scikit-learn RandomForestClassifier](https://scikit-learn.org/1.6/modules/generated/sklearn.ensemble.RandomForestClassifier.html#sklearn.ensemble.RandomForestClassifier.predict_proba).

## Test and inspect

```sh
venv/bin/python -m unittest discover -s tests -v
venv/bin/python -m pip check
venv/bin/python ai/analyzer.py
# Analyze a different log as JSON output:
venv/bin/python ai/analyzer.py /path/to/cowrie.json
```

Tests cover source attribution, sample findings, real model evaluation, benign command text, quoted delimiters, malformed records, extreme timestamps, authentication, empty states, refresh submission and HTML/script escaping. The analysis module is import-safe and can be reused by future data sources.
