"""Stream Metrics Calculator — Live Ingestion Performance Metrics.

Calculates real-time performance metrics:
- Events Per Second (EPS) over sliding windows
- Average processing latency (ms)
- Peak throughput and total events ingested

Phase 2.1 — Windows Real-Time Implementation
"""

import time
from collections import deque
from typing import Any, Dict

from ai.collection.schema import WindowsEventSchema


class StreamMetricsCalculator:
    """Calculates sliding-window EPS and ingestion latency metrics."""

    def __init__(self, window_seconds: float = 5.0) -> None:
        """Initialize StreamMetricsCalculator.

        Args:
            window_seconds: Sliding window size in seconds for EPS calculation.
        """
        self.window_seconds = window_seconds
        self._timestamps: deque[float] = deque()
        self._latencies: deque[float] = deque()
        self.total_events_processed: int = 0
        self.peak_eps: float = 0.0

    def record_event(self, event: WindowsEventSchema, latency_ms: float = 0.0) -> None:
        """Record the ingestion of an event.

        Args:
            event: The ingested event.
            latency_ms: Processing latency in milliseconds.
        """
        now = time.time()
        self._timestamps.append(now)
        self._latencies.append(latency_ms)
        self.total_events_processed += 1

        self._purge_stale(now)
        current_eps = self.get_current_eps(now)
        if current_eps > self.peak_eps:
            self.peak_eps = current_eps

    def get_current_eps(self, now: float = None) -> float:
        """Calculate current Events Per Second over the sliding window.

        Args:
            now: Current timestamp (defaults to time.time()).

        Returns:
            Current EPS float.
        """
        if now is None:
            now = time.time()

        self._purge_stale(now)
        if not self._timestamps:
            return 0.0

        count = len(self._timestamps)
        return round(count / self.window_seconds, 2)

    def get_average_latency_ms(self) -> float:
        """Return average processing latency in milliseconds over the sliding window.

        Returns:
            Average latency in ms.
        """
        if not self._latencies:
            return 0.0

        return round(sum(self._latencies) / len(self._latencies), 2)

    def get_metrics_summary(self) -> Dict[str, Any]:
        """Return complete metrics summary dictionary.

        Returns:
            Metrics summary dictionary.
        """
        now = time.time()
        current_eps = self.get_current_eps(now)
        avg_latency = self.get_average_latency_ms()

        return {
            "current_eps": current_eps,
            "peak_eps": self.peak_eps,
            "total_events_processed": self.total_events_processed,
            "average_latency_ms": avg_latency,
            "sliding_window_seconds": self.window_seconds,
        }

    def reset(self) -> None:
        """Reset all metrics to initial state."""
        self._timestamps.clear()
        self._latencies.clear()
        self.total_events_processed = 0
        self.peak_eps = 0.0

    def _purge_stale(self, now: float) -> None:
        """Remove timestamps outside the sliding window."""
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
            if self._latencies:
                self._latencies.popleft()
