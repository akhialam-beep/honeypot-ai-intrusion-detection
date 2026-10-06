import importlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

web = importlib.import_module('dashboard.dashboard')

class LiveDataTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        config = patch.dict(web.app.config, DATA_MODE='live', INGEST_TOKEN='x'*40,
                            LIVE_DATA_DB=str(Path(folder.name)/'events.sqlite3'))
        config.start()
        self.addCleanup(config.stop)
        self.client = web.app.test_client()
        self.headers = {'Authorization': 'Bearer ' + 'x'*40}

    def upload(self, events):
        return self.client.post('/api/events', json={'events': events}, headers=self.headers)

    def test_requires_token_even_with_browser_login(self):
        with self.client.session_transaction() as session:
            session['logged_in'] = True
        self.assertEqual(self.client.post('/api/events', json={'events': []}).status_code, 401)

    def test_round_trip_replacement_and_rejected_update(self):
        events = [{'eventid': 'cowrie.command.input', 'input': 'whoami', 'src_ip': '192.168.56.1'}]
        self.assertEqual(self.upload(events).status_code, 200)
        self.assertEqual(self.upload(events).status_code, 200)
        self.assertEqual(self.upload([{'eventid': 12}]).status_code, 400)
        from live_data import load_live_data
        self.assertEqual(len(load_live_data(web.app)['events']), 1)
        with self.client.session_transaction() as session:
            session['logged_in'] = True
        page = self.client.get('/dashboard').get_data(as_text=True)
        self.assertIn('192.168.56.1', page)
        self.assertIn('Receiving VM updates', page)
        self.assertNotIn('185.220.101.5', page)
        self.assertEqual(self.upload([]).status_code, 200)
        self.assertEqual(load_live_data(web.app)['events'], [])

    def test_no_sample_fallback_and_stale_state(self):
        with self.client.session_transaction() as session:
            session['logged_in'] = True
        page = self.client.get('/dashboard').get_data(as_text=True)
        self.assertIn('Waiting for the first VM upload', page)
        self.assertNotIn('185.220.101.5', page)
        self.upload([])
        import sqlite3
        with sqlite3.connect(web.app.config['LIVE_DATA_DB']) as conn:
            conn.execute("UPDATE snapshot SET received='2000-01-01T00:00:00+00:00'")
        self.assertIn('Updates delayed', self.client.get('/dashboard').get_data(as_text=True))

    def test_limits_disabled_endpoint_and_secret_requirement(self):
        self.assertEqual(self.upload([{'eventid': 'x'}]*5001).status_code, 400)
        self.assertEqual(self.client.post('/api/events', data=b' '* (4*1024*1024+1),
            content_type='application/json', headers=self.headers).status_code, 413)
        with patch.dict(web.app.config, INGEST_TOKEN=''):
            self.assertEqual(self.upload([]).status_code, 503)
        with patch.dict(web.app.config, DATA_MODE='sample'):
            self.assertEqual(self.upload([]).status_code, 404)

    def test_snapshot_above_login_body_limit(self):
        self.assertEqual(self.upload([{'eventid': 'cowrie.command.input', 'input': 'x'*1000}]*20).status_code, 200)
        self.assertEqual(self.client.post('/login', data={'x':'a'*9000}).status_code, 413)
