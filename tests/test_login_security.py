import importlib
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

web = importlib.import_module('dashboard.dashboard')

class LoginSecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = web.app.test_client()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = patch.dict(web.app.config, LOGIN_THROTTLE_DB=str(Path(self.directory.name) / 'attempts.sqlite3'),
                                 LOGIN_ATTEMPT_LIMIT=3, LOGIN_WINDOW_SECONDS=60)
        self.config.start()
        self.addCleanup(self.config.stop)

    def post(self, client=None, username='demo', password='wrong'):
        client = client or self.client
        html = client.get('/login').get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', html)
        return client.post('/login', data={'username': username, 'password': password,
                                          'csrf_token': token.group(1) if token else ''})

    def test_login_requires_csrf(self):
        response = self.client.post('/login', data={'username': 'demo', 'password': 'wrong'})
        self.assertEqual(response.status_code, 400)

    def test_throttle_applies_across_new_browser_sessions(self):
        for _ in range(3):
            self.assertNotEqual(self.post().status_code, 429)
        response = self.post(web.app.test_client())
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers['Retry-After']), 0)

    def test_throttle_expires(self):
        with patch('time.time', return_value=1000):
            for _ in range(3):
                self.post()
            self.assertEqual(self.post().status_code, 429)
        with patch('time.time', return_value=1061):
            self.assertNotEqual(self.post().status_code, 429)

    def test_unicode_username_is_handled_as_invalid(self):
        self.assertEqual(self.post(username='试验').status_code, 200)

    def test_login_and_logout_flow(self):
        from werkzeug.security import generate_password_hash
        with patch.object(web, 'DEMO_PASSWORD_HASH', generate_password_hash('test-only-password')):
            response = self.post(password='test-only-password')
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get('/dashboard').status_code, 200)
        self.assertEqual(self.client.get('/logout').status_code, 405)
        self.assertEqual(self.client.post('/logout').status_code, 400)
        with self.client.session_transaction() as session:
            token = session['csrf_token']
        self.assertEqual(self.client.post('/logout', data={'csrf_token': token}).status_code, 302)
        self.assertEqual(self.client.get('/dashboard').status_code, 302)

if __name__ == '__main__':
    unittest.main()
