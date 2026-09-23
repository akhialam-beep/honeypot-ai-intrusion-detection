import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

web = importlib.import_module('dashboard.dashboard')

class ActivityFiltersTests(unittest.TestCase):
    def setUp(self):
        self.client = web.app.test_client()
        with self.client.session_transaction() as session:
            session['logged_in'] = True
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        path = Path(self.directory.name) / 'events.json'
        rows = [{'eventid': 'cowrie.command.input' if i % 2 else 'cowrie.login.failed',
                 'src_ip': '192.0.2.1' if i % 3 else '192.0.2.2',
                 'timestamp': f'2026-09-01T00:00:{i:02d}Z', 'input': 'pwd'} for i in range(45)]
        path.write_text('\n'.join(json.dumps(row) for row in rows))
        self.logs = patch.object(web, 'LOG_FILE', str(path))
        self.logs.start()
        self.addCleanup(self.logs.stop)

    def activity(self, query=''):
        response = self.client.get('/dashboard' + query)
        self.assertEqual(response.status_code, 200)
        text = response.get_data(as_text=True)
        # The section is the user-visible result, not the other dashboard summaries.
        return text.split('id="activity"', 1)[1].split('</section>', 1)[0]

    def test_view_all_reaches_older_events_and_pages(self):
        latest = self.activity()
        self.assertNotIn('2026-09-01T00:00:00Z', latest)
        page = self.activity('?view=all&page=2')
        self.assertTrue('2026-09-01T00:00:00Z' in page, 'View all must reach records outside the latest ten')
        self.assertTrue('26–45 of 45' in page)

    def test_combined_filters_limit_only_the_activity_results(self):
        result = self.activity('?view=all&event_type=cowrie.command.input&source_ip=192.0.2.1')
        self.assertNotIn('2026-09-01T00:00:42Z', result)
        self.assertIn('2026-09-01T00:00:43Z', result)
        self.assertTrue('15 matching events' in result)

    def test_unknown_filter_has_honest_empty_state(self):
        result = self.activity('?view=all&source_ip=192.0.2.99')
        self.assertTrue('No activity matches these filters.' in result)
        self.assertNotIn('2026-09-01T00:00:44Z', result)

    def test_invalid_page_is_bounded(self):
        for value in ['no', '-100', '9999999999999999999999']:
            result = self.activity('?view=all&page=' + value)
            self.assertTrue('Page ' in result)

if __name__ == '__main__':
    unittest.main()
