"""Unit tests for timestamp semantics; tests are independent of agent services."""

import unittest

from domain.event_lag import event_delivery_lag_seconds


class EventDeliveryLagTests(unittest.TestCase):
    def test_uses_actual_monotonic_timestamp_delta(self):
        lag, reason = event_delivery_lag_seconds(1_000_000_000, 1_007_500_000)
        self.assertAlmostEqual(lag, 0.0075)
        self.assertIsNone(reason)

    def test_zero_kernel_timestamp_is_unavailable(self):
        lag, reason = event_delivery_lag_seconds(0, 10)
        self.assertIsNone(lag)
        self.assertEqual(reason, "missing_kernel_timestamp")

    def test_future_kernel_timestamp_is_unavailable(self):
        lag, reason = event_delivery_lag_seconds(20, 10)
        self.assertIsNone(lag)
        self.assertEqual(reason, "future_kernel_timestamp")


if __name__ == "__main__":
    unittest.main()
