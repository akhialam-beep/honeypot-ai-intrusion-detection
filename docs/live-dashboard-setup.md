# Demo 2: VM to hosted dashboard

The VM remains the authoritative MariaDB store. A scheduled HTTPS upload replaces
one dashboard snapshot with the latest 5,000 rows. The hosted dashboard runs the
existing analyzer on those events. Its totals can differ from analyze_db.py,
which reads all rows. No database port or inbound VM connection is required.
No captured passwords are uploaded. Existing analysis/import cron jobs are unchanged.

## Keyauna: Render setup

Review and merge the integration branch, then deploy that commit to the existing
service. Keep the existing start command. Use `pip install -r requirements.txt`
for the web build. MariaDB's native connector is now in requirements-vm.txt;
the hosted app does not connect directly to MariaDB.

Set these environment variables in the Render service:

- DATA_MODE: live
- INGEST_TOKEN: a new random secret of at least 32 characters, shared securely
  with Binta. Generate with `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
- SECRET_KEY: a stable random secret, distinct from INGEST_TOKEN.
- DEMO_PASSWORD: a strong dashboard password (or set DEMO_PASSWORD_HASH).
  Replace the shipped demo password before uploading real records.

The default LIVE_DATA_DB is instance/live-events.sqlite3. This is a disposable
cache on Render's ephemeral filesystem. A restart/redeploy can erase it: the UI
shows a waiting state until the next upload, never sample data. If a persistent
disk is already available, set LIVE_DATA_DB to a path inside its mount point.
Do not purchase hosting resources without team agreement. This implementation
supports one service instance, including multiple Gunicorn workers sharing its
filesystem; it does not support multiple independent service instances.

Official references:
https://render.com/docs/configure-environment-variables
https://render.com/docs/free
https://render.com/docs/disks

## Binta: install the VM sender

From Windows PowerShell in the project folder:

```powershell
scp database/push_dashboard.py bbinta@192.168.56.102:/home/bbinta/honeypot-ai-intrusion-detection/database/push_dashboard.py
```

The existing VM environment already has mariadb installed. For a fresh VM
environment use `python -m pip install -r requirements-vm.txt` with native
MariaDB build prerequisites available. Do not install the VM requirements on Render.

In Ubuntu, as bbinta, create the upload configuration securely. Paste the same
INGEST_TOKEN Keyauna configured; the prompt hides it. Never commit this file.

```bash
python3 - <<'PY'
import getpass, json, os
from pathlib import Path
folder = Path.home() / '.config/honeypot-ai'
folder.mkdir(parents=True, exist_ok=True, mode=0o700)
os.chmod(folder, 0o700)
token = getpass.getpass('Render upload token: ')
if len(token) < 32:
    raise SystemExit('Token must be at least 32 characters.')
path = folder / 'dashboard-upload.json'
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.fchmod(fd, 0o600)
with os.fdopen(fd, 'w') as file:
    json.dump({'url': 'https://honeypot-ai-intrusion-detection.onrender.com/api/events', 'token': token}, file)
PY
```

This reuses bbinta's existing `.config/honeypot-ai/db-password` file.
Test after Keyauna's deployment is ready:

```bash
cd /home/bbinta/honeypot-ai-intrusion-detection
.venv313/bin/python -m database.push_dashboard
```

After a successful upload, add this line with `crontab -e` as bbinta,
preserving both existing jobs (the importer belongs to the cowrie user):

```cron
* * * * * cd /home/bbinta/honeypot-ai-intrusion-detection && /usr/bin/flock -n /home/bbinta/.config/honeypot-ai/dashboard-upload.lock /home/bbinta/honeypot-ai-intrusion-detection/.venv313/bin/python -m database.push_dashboard >> /home/bbinta/.local/state/honeypot-ai/dashboard-upload.log 2>&1
```

The log directory already exists from analysis setup. Uploads time out after
45 seconds; failed runs exit nonzero and the next minute retries. Initial Render
startup may take longer; retry after the service wakes. Do not run a manual upload
concurrently with cron. One VM sender is supported. Snapshot bodies are limited
to 4 MiB and each field to 16,384 characters; rejected snapshots leave the last
good snapshot intact. Logs need periodic rotation. A snapshot replaces rather
than appends events, so retrying does not duplicate rows. This does not repair
any duplicates already present in MariaDB.

## End-to-end verification (still required)

1. Sign into the hosted dashboard. Confirm it says MariaDB snapshot and shows a
   UTC receipt time. The map remains explicitly labeled as preset demo locations.
2. In the authorized Cowrie test session, run `whoami`, then exit.
3. Allow approximately 2–3 minutes for import, upload and browser refresh.
4. Confirm event/command totals and latest recorded activity change. Receipt time
   describes the upload, not when an attacker event occurred.
5. Stop uploads for over three minutes and refresh: the dashboard should say
   updates are delayed while retaining the last snapshot.

The practice AI model is unchanged: eight fabricated training examples, not a
validated attack probability. This integration has local automated checks; the
real VM/Render connection must still be tested by the team.

## Rollback

Set DATA_MODE=sample on Render to restore the original sample dashboard and
disable the upload endpoint. Remove only the new dashboard-upload cron line on
the VM. The importer and analysis jobs continue unchanged.
