\# Demo 2: Database Integration and Automation

Contributor: Binta Bah



\## Verified functionality

\- Cowrie captures SSH activity on port 2222.

\- The importer stores events in MariaDB automatically every minute.

\- database/analyze\_db.py reads MariaDB events and calls Akhi's analyzer.

\- Analysis runs automatically every minute and saves latest\_analysis.json.

\- Dashboard integration is still pending.



\## Current Ubuntu VM setup

\- Database: cowrie\_db

\- Table: cowrie\_events

\- Database user: cowrie\_app

\- Cowrie installation: /home/cowrie/cowrie

\- Project: /home/bbinta/honeypot-ai-intrusion-detection

\- Analyzer Python environment: .venv313 (Python 3.13)

\- MariaDB Python connector: 1.1.14



The deployed importer is /home/cowrie/cowrie/import\_cowrie.py.

The repository copy is database/import\_cowrie.py.



\## Credentials

Each password file contains only the database password.

Files have permission 600; their containing private directories have permission 700.



\- Importer: /home/cowrie/.config/cowrie-db-password

&#x20; Owner: cowrie

\- Analyzer: /home/bbinta/.config/honeypot-ai/db-password

&#x20; Owner: bbinta



Passwords are stored outside the repository and must not be committed.

Both scripts fall back to an interactive password prompt if their file is missing.

Unattended runs require the password files to exist and be readable.



\## Importer schedule

Edit with sudo -u cowrie crontab -e:



```cron

\* \* \* \* \* /usr/bin/flock -n /home/cowrie/.config/cowrie-import.lock /home/cowrie/cowrie/cowrie-env/bin/python /home/cowrie/cowrie/import\_cowrie.py >> /home/cowrie/cowrie/import\_cowrie.log 2>\&1

```



\## Analyzer schedule

Edit with crontab -e as bbinta:



```cron

\* \* \* \* \* cd /home/bbinta/honeypot-ai-intrusion-detection \&\& /usr/bin/flock -n /home/bbinta/.local/state/honeypot-ai/analyze.lock /home/bbinta/honeypot-ai-intrusion-detection/.venv313/bin/python -m database.analyze\_db >> /home/bbinta/.local/state/honeypot-ai/analyze.log 2>\&1

```



Run the analyzer manually once before scheduling it to create the output directory.

These paths describe Binta's VM and must be adjusted for other installations.

Cron entries are configured separately; cloning the repository does not install them.



\## Results and verification

Latest results:

\~/.local/state/honeypot-ai/latest\_analysis.json



Analyzer log:

\~/.local/state/honeypot-ai/analyze.log



A fresh SSH test produced 19 automatically imported events.

A later scheduled analysis read 163 database events.

The results file was confirmed to update automatically.



The importer and analyzer have independent schedules.

Allow approximately two minutes for new activity to reach the saved analysis.

The VM, MariaDB, Cowrie, and cron must be running.



\## Current limitations

\- The importer reads the current cowrie.json file, not rotated log files.

\- Duplicate handling relies on the existing database unique key.

\- The analyzer reads all stored events on each run.

\- Log rotation for the automation output logs is not configured.

\- The practice model uses eight synthetic examples; its score is not an attack probability.

\- The saved analysis file has not yet been connected to the dashboard.

