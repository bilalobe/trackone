"""Negative controls for recovery qualification evidence and accounting."""
import copy
import hashlib
import unittest

from recovery_assertions import (
    REQUIRED_SCENARIOS, assert_artifacts, assert_chain, assert_complete, assert_occurrences,
)


class RecoveryAssertions(unittest.TestCase):
    def test_duplicate_payloads_are_occurrences(self):
        assert_occurrences(["aa", "aa", "bb"], ["bb", "aa", "aa"])

    def test_missing_acknowledged_occurrence_fails(self):
        with self.assertRaisesRegex(AssertionError, "multiplicity"):
            assert_occurrences(["aa", "aa"], ["aa"])

    def test_extra_occurrence_fails(self):
        with self.assertRaisesRegex(AssertionError, "multiplicity"):
            assert_occurrences(["aa"], ["aa", "aa"])

    def test_changed_or_missing_artifact_fails(self):
        for current in ({"0": "bb"}, {}):
            with self.subTest(current=current), self.assertRaisesRegex(AssertionError, "artifact changed"):
                assert_artifacts({"0": "aa"}, current)

    def fixture(self):
        raw = b"artifact"
        digest = hashlib.sha256(raw).hexdigest()
        snapshot = {"segments": [{"number": "0", "artifact": raw.hex(), "sha256": digest, "reason": "recovery"}],
                    "records": [{"segment": "0", "ordinal": "0", "record": "aa"}],
                    "state": {"next": "1", "predecessor": raw.hex()}}
        segment = {"segment_number": 0, "prev_segment_sha256": bytes(32), "close_reason": "recovery",
                   "record_count": 1, "commitment_profile_id": "profile"}
        return snapshot, segment

    def test_chain_controls(self):
        snapshot, segment = self.fixture()
        self.assertEqual(assert_chain(snapshot, lambda _: segment), "profile")
        mutations = (
            ("gap", lambda s, d: s["segments"][0].update(number="1")),
            ("duplicate", lambda s, d: s["segments"].append(copy.deepcopy(s["segments"][0]))),
            ("digest", lambda s, d: s["segments"][0].update(artifact="aa")),
            ("predecessor", lambda s, d: d.update(prev_segment_sha256=bytes([1]) * 32)),
            ("closure", lambda s, d: d.update(close_reason="manual")),
            ("count", lambda s, d: d.update(record_count=2)),
            ("ordinal", lambda s, d: s["records"][0].update(ordinal="1")),
            ("next", lambda s, d: s["state"].update(next="2")),
            ("state predecessor", lambda s, d: s["state"].update(predecessor="bb")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label), self.assertRaises(AssertionError):
                s, d = copy.deepcopy(snapshot), copy.deepcopy(segment)
                mutate(s, d)
                assert_chain(s, lambda _: d)

    def report(self):
        return {"commit": "a" * 40, "profile_uuid": "profile", "source_sha256": {"file": "b" * 64},
                "scenarios": [{"name": name, "status": "passed", "fault_observed": True,
                               "verification_reports": ["independent.json", "trackone.json"]}
                              for name in REQUIRED_SCENARIOS]}

    def test_complete_report(self):
        assert_complete(self.report())

    def test_missing_duplicate_failed_unobserved_unverified_scenario_fails(self):
        for kind in ("missing", "duplicate", "failed", "unobserved", "unverified"):
            report = self.report()
            if kind == "missing":
                report["scenarios"].pop()
            elif kind == "duplicate":
                report["scenarios"].append(report["scenarios"][0])
            elif kind == "failed":
                report["scenarios"][0]["status"] = "failed"
            elif kind == "unobserved":
                report["scenarios"][0]["fault_observed"] = False
            else:
                report["scenarios"][0]["verification_reports"] = []
            with self.subTest(kind=kind), self.assertRaises(AssertionError):
                assert_complete(report)

    def test_missing_provenance_fails(self):
        for field in ("commit", "profile_uuid", "source_sha256"):
            report = self.report()
            del report[field]
            with self.subTest(field=field), self.assertRaisesRegex(AssertionError, "provenance"):
                assert_complete(report)


if __name__ == "__main__":
    unittest.main()
