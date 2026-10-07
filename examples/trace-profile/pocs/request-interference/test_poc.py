import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import poc


class AccountingTests(unittest.TestCase):
    def test_id_normalization_and_rejection(self):
        raw = bytes(range(8))
        self.assertEqual(poc.normalize_id(raw.hex().upper(), 8), raw.hex())
        self.assertEqual(poc.normalize_id(base64.b64encode(raw).decode(), 8), raw.hex())
        for value in ("00" * 8, "garbage", "aa" * 16, None):
            with self.assertRaises(ValueError):
                poc.normalize_id(value, 8)

    def test_short_tempo_hex_is_explicit_not_generic(self):
        short = "123456789abcdef" * 2 + "1"
        self.assertEqual(poc.normalize_id(short, 16, allow_short_hex=True), "0" + short)
        with self.assertRaises(ValueError):
            poc.normalize_id(short, 16)

    def test_accounting_sums_self_and_preserves_overlapping_cumulative(self):
        raw = {"flamegraph": {"total": "10", "names": ["root", "hot"],
               "levels": [{"values": [0, 10, 0, 0]}, {"values": [0, 10, 10, 1]}]}}
        value = poc.flame_summary(raw)
        self.assertEqual(value["total_ns"], 10)
        self.assertEqual(value["self_sum_ns"], 10)
        self.assertEqual(sum(row["cumulative_ns"] for row in value["functions"]), 20)

    def test_missing_is_not_execution_or_causal_claim(self):
        self.assertEqual(poc.flame_summary({})["state"], "no_matching_samples")
        self.assertEqual(poc.flame_summary({})["total_ns"], 0)

    def test_broken_accounting_rejected(self):
        with self.assertRaises(ValueError):
            poc.flame_summary({"flamegraph": {"total": 10, "names": ["hot"],
                              "levels": [{"values": [0, 10, 9, 0]}]}})

    def test_backend_failure_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary, patch("poc.request", side_effect=OSError("backend unavailable")):
            out = Path(temporary)
            value = poc.captured(out, "aggregate", "/unavailable", {"start": 1, "end": 2})
            self.assertEqual(value, {"collection_error": "backend unavailable"})
            self.assertEqual(json.loads((out / "raw" / "aggregate.json").read_text()), value)
            self.assertEqual(json.loads((out / "raw" / "aggregate.request.json").read_text())["body"], {"start": 1, "end": 2})

    def test_expired_retry_retains_actual_partial_and_archives_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary)
            expired = {"trace_search": {"collection_error": "deadline reached"}, "exemplars": [],
                       "aggregate": {"collection_error": "deadline reached"}}
            partial = {"trace_search": {"traces": [{"traceID": "observed"}]}, "exemplars": [],
                       "aggregate": {"total_ns": 0}}
            poc.save(out / "summary.json", expired)
            poc.save(out / "raw" / "search.json", expired["trace_search"])
            source = out / "collection-attempts" / "0"
            poc.save(source / "summary.json", partial)
            poc.save(source / "raw" / "search.json", partial["trace_search"])
            selected = poc.retain_best_partial(out)
            self.assertEqual(selected["trace_search"], partial["trace_search"])
            self.assertEqual(json.loads((out / "deadline-response" / "summary.json").read_text()), expired)
            self.assertEqual(json.loads((out / "raw" / "search.json").read_text()), partial["trace_search"])


if __name__ == "__main__":
    unittest.main()
