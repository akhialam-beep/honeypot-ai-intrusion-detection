import json
from pathlib import Path
import tempfile
import unittest

try:
    from ai import analyzer
except FileNotFoundError:
    analyzer = None


ROOT = Path(__file__).resolve().parents[1]


def command(text, ip="192.0.2.1"):
    return {"eventid": "cowrie.command.input", "input": text, "src_ip": ip}


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(analyzer, "Analyzer must import without opening a hardcoded log file")

    def test_sample_findings_have_evidence_and_source_attribution(self):
        batch = analyzer.load_event_log(ROOT / "sample_data/cowrie.json")
        result = analyzer.analyze_events(batch["events"])
        self.assertEqual(result["status"], "SUSPICIOUS")
        self.assertEqual(result["priority"], "High")
        self.assertEqual(result["event_count"], 8)
        self.assertEqual(result["source_count"], 2)
        findings = {item["id"]: item for item in result["findings"]}
        self.assertEqual(findings["download"]["count"], 1)
        self.assertEqual(findings["download"]["evidence"][0]["ip"], "185.220.101.5")
        self.assertIn("wget", findings["download"]["evidence"][0]["detail"])
        self.assertIn("account-files", findings)
        self.assertEqual(sum(row["event_count"] for row in result["sources"]), 8)

    def test_empty_and_unsupported_data_are_not_declared_safe(self):
        empty = analyzer.analyze_events([])
        self.assertEqual(empty["status"], "NO DATA")
        self.assertIsNone(empty["model"]["suspicious_signal"])
        unsupported = analyzer.analyze_events([{"eventid": "cowrie.session.connect"}])
        self.assertEqual(unsupported["status"], "LIMITED DATA")

    def test_benign_text_does_not_match_command_substrings(self):
        result = analyzer.analyze_events([command("echo 'wget https://example.org'")])
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["status"], "NO INDICATORS")

    def test_quoted_and_escaped_separators_do_not_create_commands(self):
        for text in ['echo ";" wget https://example.org/file', 'echo "|" cat /etc/shadow',
                     r'echo \; wget https://example.org/file', 'echo ok # ; wget https://example.org/file']:
            with self.subTest(text=text):
                self.assertEqual(analyzer.command_indicators(text), set())
        self.assertIn("download", analyzer.command_indicators('whoami; curl "https://example.org/file"'))

    def test_additional_shell_indicators_are_evidence_based(self):
        cases = [
            ("tee -a ~/.ssh/authorized_keys", "ssh-keys", "High"),
            ("crontab -e", "cron-change", "Medium"),
            ("rm -rf /tmp/unneeded", "recursive-delete", "High"),
        ]
        for line, rule, severity in cases:
            with self.subTest(line=line):
                result = analyzer.analyze_events([command(line)])
                finding = next(item for item in result["findings"] if item["id"] == rule)
                self.assertEqual(finding["severity"], severity)
                self.assertEqual(finding["count"], 1)
        self.assertEqual(analyzer.command_indicators("echo 'rm -rf /'"), set())

    def test_extreme_timestamps_do_not_prevent_analysis(self):
        event = command("pwd")
        for timestamp in ['0001-01-01T00:00:00+01:00', '9999-12-31T23:59:59-01:00']:
            event["timestamp"] = timestamp
            result = analyzer.analyze_events([event])
            self.assertEqual(result["event_count"], 1)
            self.assertIsNone(result["first_event"])

    def test_login_findings_group_by_source_not_total(self):
        events = [{"eventid": "cowrie.login.failed", "src_ip": f"192.0.2.{i}"} for i in range(3)]
        self.assertNotIn("failed-logins", [f["id"] for f in analyzer.analyze_events(events)["findings"]])
        for event in events:
            event["src_ip"] = "192.0.2.1"
        finding = next(f for f in analyzer.analyze_events(events)["findings"] if f["id"] == "failed-logins")
        self.assertEqual(finding["count"], 3)

    def test_single_download_attempt_is_visible_even_if_model_signal_is_low(self):
        result = analyzer.analyze_events([command("/usr/bin/curl https://example.org/file")])
        self.assertEqual(result["priority"], "High")
        self.assertEqual(result["findings"][0]["id"], "download")
        self.assertIn("attempt", result["findings"][0]["description"].lower())

    def test_model_uses_real_demo_classifier_and_reports_limits(self):
        events = [command("true")] * 15 + [{"eventid": "cowrie.login.failed", "src_ip": "192.0.2.1"}] * 5
        result = analyzer.analyze_events(events)
        self.assertTrue(result["model"]["available"])
        self.assertEqual(result["model"]["training_examples"], 8)
        self.assertGreater(result["model"]["suspicious_signal"], 50)
        self.assertEqual(result["model"]["features"]["commands"], 15)
        self.assertIn("eight made-up examples", result["model"]["limitation"].lower())
        self.assertIs(analyzer.get_model(), analyzer.get_model())

    def test_loader_ignores_malformed_rows_and_missing_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json"
            path.write_text('\n'.join([json.dumps(command("pwd")), '{bad', '[]', 'null',
                                       '{"eventid":"cowrie.command.input","input":{}}',
                                       '{"eventid":"cowrie.login.failed"}']))
            batch = analyzer.load_event_log(path)
            self.assertEqual(len(batch["events"]), 2)
            self.assertEqual(batch["skipped"], 4)
            self.assertEqual(analyzer.analyze_events(batch["events"])["event_count"], 2)
            missing = analyzer.load_event_log(Path(directory) / "missing.json")
            self.assertEqual(missing["events"], [])
            self.assertTrue(missing["error"])

    def test_evidence_preview_is_bounded_but_counts_are_complete(self):
        result = analyzer.analyze_events([command("wget https://example.org/file")] * 30)
        finding = next(f for f in result["findings"] if f["id"] == "download")
        self.assertEqual(finding["count"], 30)
        self.assertLessEqual(len(finding["evidence"]), 3)


if __name__ == "__main__":
    unittest.main()
