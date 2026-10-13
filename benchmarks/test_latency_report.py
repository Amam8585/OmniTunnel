import unittest
from latency_report import quantile, summarize

class LatencyReportTest(unittest.TestCase):
    def test_quantiles_are_interpolated(self):
        self.assertEqual(quantile([10, 20, 30], 0.95), 29.0)
        self.assertEqual(quantile([10, 20, 30], 0.99), 29.8)
        self.assertIsNone(quantile([], 0.95))

    def test_kernel_vs_application_are_not_conflated(self):
        log = """64 bytes from peer: icmp_seq=1 ttl=64 time=10.0 ms
64 bytes from peer: icmp_seq=2 ttl=64 time=20.0 ms
64 bytes from peer: icmp_seq=3 ttl=64 time=30.0 ms
"""
        result = summarize(log, 4)
        self.assertEqual(result["loss_percent"], 25)
        self.assertEqual(result["received_packets"], 3)
        self.assertEqual(result["rtt_p95_ms"], 29)
        self.assertEqual(result["rtt_p99_ms"], 29.8)
        self.assertIsNone(result["application_goodput_mbps"])

    def test_no_data_is_explicitly_null(self):
        result = summarize("", 10)
        self.assertEqual(result["loss_percent"], 100)
        self.assertIsNone(result["rtt_p99_ms"])

    def test_invalid_offered_load_is_rejected(self):
        with self.assertRaises(ValueError):
            summarize("time=1.0 ms\ntime=2.0 ms\n", 1)

if __name__ == "__main__":
    unittest.main()
