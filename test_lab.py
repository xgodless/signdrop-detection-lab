# test_lab.py

from pathlib import Path
import unittest

from lab import analyze_manifest, parse_time, read_events


FIXTURES = Path(__file__).parent / "fixtures"


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        report = analyze_manifest(FIXTURES / "scenarios.json")
        cls.captures = {capture["id"]: capture for capture in report["captures"]}

    def test_fixture_results(self):
        expected = {
            "write_then_load": (("matched", 1), ("matched", 1)),
            "write_without_matching_load": (("matched", 1), ("no_match", 0)),
            "image_load_unavailable": (("matched", 1), ("insufficient_data", 0)),
            "benign_control": (("no_match", 0), ("no_match", 0)),
            "truncated_window": (("matched", 1), ("insufficient_data", 0)),
        }
        self.assertEqual(self.captures.keys(), expected.keys())
        for capture_id, (expected_write, expected_pair) in expected.items():
            with self.subTest(capture=capture_id):
                capture = self.captures[capture_id]
                write = capture["file_create"]
                pair = capture["write_then_load"]
                self.assertEqual((write["status"], write["count"]), expected_write)
                self.assertEqual((pair["status"], pair["count"]), expected_pair)

    def test_match_contains_both_events(self):
        capture = self.captures["write_then_load"]
        matches = capture["write_then_load"]["matches"]
        self.assertEqual(len(matches), 1)
        match = matches[0]
        self.assertEqual(match["write"]["record_id"], 101)
        self.assertEqual(match["load"]["record_id"], 102)

    def test_coverage_gaps(self):
        missing = self.captures["image_load_unavailable"]
        truncated = self.captures["truncated_window"]
        self.assertEqual(missing["write_then_load"]["coverage_gaps"], ["image_load_unavailable"])
        self.assertEqual(truncated["truncated_write_record_ids"], [109])
        self.assertEqual(
            truncated["write_then_load"]["coverage_gaps"],
            ["capture_ends_before_correlation_window"],
        )

    def test_wrong_host(self):
        start = parse_time("2026-11-24T07:00:00Z")
        end = parse_time("2026-11-24T07:05:00Z")
        with self.assertRaisesRegex(ValueError, "expected host"):
            read_events(FIXTURES / "sysmon.xml", "ANOTHER-HOST", start, end)


if __name__ == "__main__":
    unittest.main()
