import importlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


dashboard = importlib.import_module("dashboard.dashboard")


class DashboardAnalysisTests(unittest.TestCase):
    def setUp(self):
        self.client = dashboard.app.test_client()

    def sign_in(self):
        with self.client.session_transaction() as session:
            session["logged_in"] = True
            session["username"] = "demo"

    def test_analysis_requires_login(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

    def test_refresh_submits_a_new_request_instead_of_just_jumping_to_fragment(self):
        self.sign_in()
        html = self.client.get("/dashboard").get_data(as_text=True)
        self.assertTrue('name="refresh"' in html and 'type="submit"' in html)

    def test_analysis_is_connected_to_the_shipped_data(self):
        self.sign_in()
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        for text in ['id="ai-analysis"', 'href="#ai-analysis"', "Remote download command",
                     "Account-file access command", "185.220.101.5", "Recommended next steps",
                     "Demonstration model", "Refresh analysis"]:
            self.assertIn(text, html)

    def test_untrusted_log_text_is_escaped_in_markup_and_script_data(self):
        self.sign_in()
        payload = '</script><script>alert(1)</script>'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cowrie.json"
            events = [{"eventid": "cowrie.command.input", "input": "wget https://example.org/ " + payload, "src_ip": payload},
                      {"eventid": payload}]
            path.write_text("\n".join(json.dumps(event) for event in events))
            with patch.object(dashboard, "LOG_FILE", str(path)):
                response = self.client.get("/dashboard")
            self.assertEqual(response.status_code, 200)
            html = response.get_data(as_text=True)
            self.assertNotIn(payload, html)
            self.assertIn("&lt;/script&gt;", html)

    def test_missing_log_has_an_honest_empty_state(self):
        self.sign_in()
        with tempfile.TemporaryDirectory() as directory, patch.object(dashboard, "LOG_FILE", str(Path(directory) / "absent.json")):
            response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("NO DATA", html)
        self.assertIn("event log is unavailable", html)

    def test_malformed_rows_do_not_crash_dashboard_and_are_reported(self):
        self.sign_in()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cowrie.json"
            path.write_text('[]\nnull\n{bad\n{"eventid":"cowrie.command.input","input":"pwd"}')
            with patch.object(dashboard, "LOG_FILE", str(path)):
                response = self.client.get("/dashboard")
            self.assertEqual(response.status_code, 200)
            self.assertIn("3 invalid records skipped", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
