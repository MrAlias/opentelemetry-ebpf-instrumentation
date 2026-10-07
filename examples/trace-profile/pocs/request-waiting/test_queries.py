import unittest
from run import accounting, normalized, spans


class QueryTests(unittest.TestCase):
    def test_ids_have_exact_width_and_nonzero_values(self):
        self.assertEqual(normalized("AQIDBAUGBwg=", 8), "0102030405060708")
        self.assertEqual(normalized("0102030405060708", 8), "0102030405060708")
        self.assertEqual(normalized("123456789abcdef0123456789abcdef", 16, short_hex=True), "0123456789abcdef0123456789abcdef")
        for value in ("0000000000000000", "01", "not-an-id"):
            with self.assertRaises(ValueError):
                normalized(value, 8)

    def test_self_values_sum_once_across_nested_frames(self):
        graph = {"names": ["root", "wait", "other"], "total": "11", "levels": [
            {"values": [0, 11, 0, 0]}, {"values": [0, 7, 7, 1, 0, 4, 4, 2]}]}
        result = accounting(graph)
        self.assertEqual(result["total_ns"], 11)
        self.assertEqual(result["self_sum_ns"], 11)
        graph["total"] = 12
        with self.assertRaises(ValueError):
            accounting(graph)

    def test_span_matching_reads_payload_ids_without_timestamps(self):
        span = {"spanId": "0102030405060708", "name": "request"}
        self.assertEqual(spans({"batches": [{"scopeSpans": [{"spans": [span]}]}]}), [span])


if __name__ == "__main__":
    unittest.main()
