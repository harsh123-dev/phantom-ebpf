"""Pure event-ingestion lag semantics shared by the agent and unit tests."""

from __future__ import annotations


def event_delivery_lag_seconds(
    kernel_timestamp_ns: int, callback_monotonic_ns: int
) -> tuple[float | None, str | None]:
    """Return kernel-event-to-userspace-callback lag and an invalid reason.

    Both values are monotonic nanoseconds. The caller supplies the actual
    kernel timestamp and callback-entry timestamp; this function never creates
    or substitutes timestamps. A zero source time or negative delta is
    excluded from measurement.
    """
    if kernel_timestamp_ns <= 0:
        return None, "missing_kernel_timestamp"
    delta_ns = callback_monotonic_ns - kernel_timestamp_ns
    if delta_ns < 0:
        return None, "future_kernel_timestamp"
    return delta_ns / 1_000_000_000, None
