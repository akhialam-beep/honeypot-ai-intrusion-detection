import unittest
from ai import analyzer


class BruteForceTests(unittest.TestCase):

    def make_events(self, timestamps, ip="192.0.2.10"):
        return [
            {
                "eventid": "cowrie.login.failed",
                "src_ip": ip,
                "timestamp": timestamp,
                "username": "root",
            }
            for timestamp in timestamps
        ]

    def test_five_failures_within_five_minutes(self):
        events = self.make_events([
            "2026-10-20T12:00:00Z",
            "2026-10-20T12:01:00Z",
            "2026-10-20T12:02:00Z",
            "2026-10-20T12:03:00Z",
            "2026-10-20T12:04:00Z",
        ])
        alerts = analyzer.detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["ip"], "192.0.2.10")

    def test_failures_spread_over_more_than_five_minutes(self):
        events = self.make_events([
            "2026-10-20T12:00:00Z",
            "2026-10-20T12:02:00Z",
            "2026-10-20T12:04:00Z",
            "2026-10-20T12:06:00Z",
            "2026-10-20T12:08:00Z",
        ])
        alerts = analyzer.detect_brute_force(events)
        self.assertEqual(alerts, [])

    def test_different_ips_are_not_combined(self):
        events = self.make_events([
            "2026-10-20T12:00:00Z",
            "2026-10-20T12:01:00Z",
            "2026-10-20T12:02:00Z",
        ], ip="192.0.2.10")
        events += self.make_events([
            "2026-10-20T12:00:00Z",
            "2026-10-20T12:01:00Z",
        ], ip="192.0.2.11")
        alerts = analyzer.detect_brute_force(events)
        self.assertEqual(alerts, [])


if __name__ == "__main__":
    unittest.main()
