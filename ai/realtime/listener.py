"""Real-Time Stream Listener — Background Event Dispatcher & Orchestrator.

Manages a dedicated non-blocking worker thread that pulls events from the
RealTimeEventBuffer and dispatches them to registered real-time subscribers.

Phase 2.1 — Windows Real-Time Implementation
"""

import logging
import threading
import time
import uuid
from typing import Any, Callable, Dict, Optional

from ai.collection.schema import WindowsEventSchema
from ai.realtime.buffer import RealTimeEventBuffer
from ai.realtime.metrics import StreamMetricsCalculator

logger = logging.getLogger("RealTimeStreamListener")

# Type alias for subscriber callback functions
EventCallback = Callable[[WindowsEventSchema], None]


class RealTimeStreamListener:
    """Non-blocking background worker that dispatches buffer events to subscribers."""

    def __init__(self, buffer: Optional[RealTimeEventBuffer] = None) -> None:
        """Initialize RealTimeStreamListener.

        Args:
            buffer: RealTimeEventBuffer instance (creates default if None).
        """
        self.buffer = buffer or RealTimeEventBuffer()
        self.metrics = StreamMetricsCalculator()
        self._subscribers: Dict[str, EventCallback] = {}
        self._is_running: bool = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def subscribe(self, callback_fn: EventCallback) -> str:
        """Register a subscriber callback function.

        Args:
            callback_fn: Function taking a WindowsEventSchema instance.

        Returns:
            Unique subscriber ID string.
        """
        sub_id = str(uuid.uuid4())
        with self._lock:
            self._subscribers[sub_id] = callback_fn
        logger.info(f"Registered real-time subscriber: {sub_id}")
        return sub_id

    def unsubscribe(self, subscriber_id: str) -> bool:
        """Unregister a subscriber.

        Args:
            subscriber_id: Unique subscriber ID.

        Returns:
            True if found and removed, False otherwise.
        """
        with self._lock:
            if subscriber_id in self._subscribers:
                del self._subscribers[subscriber_id]
                logger.info(f"Unregistered real-time subscriber: {subscriber_id}")
                return True
        return False

    def subscriber_count(self) -> int:
        """Return number of registered subscribers."""
        with self._lock:
            return len(self._subscribers)

    def start_listening(self) -> None:
        """Start non-blocking background dispatch thread."""
        with self._lock:
            if self._is_running:
                logger.warning("RealTimeStreamListener is already running.")
                return
            self._is_running = True
            self._thread = threading.Thread(target=self._worker_loop, daemon=True, name="RealTimeStreamListenerThread")
            self._thread.start()
        logger.info("RealTimeStreamListener started on background daemon thread.")

    def stop_listening(self, timeout: float = 2.0) -> None:
        """Stop background dispatch thread.

        Args:
            timeout: Maximum seconds to wait for thread join.
        """
        with self._lock:
            if not self._is_running:
                return
            self._is_running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("RealTimeStreamListener stopped.")

    def process_next(self) -> Optional[WindowsEventSchema]:
        """Manually pull and dispatch next event (useful for testing)."""
        event = self.buffer.get()
        if event is None:
            return None

        start_time = time.time()
        self._dispatch_event(event)
        latency_ms = (time.time() - start_time) * 1000.0
        self.metrics.record_event(event, latency_ms=latency_ms)
        return event

    def is_running(self) -> bool:
        """Return True if background worker thread is running."""
        with self._lock:
            return self._is_running

    def get_status(self) -> Dict[str, Any]:
        """Return comprehensive listener health and performance status."""
        buffer_status = self.buffer.get_status()
        metrics_summary = self.metrics.get_metrics_summary()

        return {
            "status": "running" if self.is_running() else "stopped",
            "subscriber_count": self.subscriber_count(),
            "buffer": buffer_status,
            "metrics": metrics_summary,
        }

    # ──────────────────────────────────────────────────────────
    # Private Worker Loop
    # ──────────────────────────────────────────────────────────

    def _worker_loop(self) -> None:
        """Background thread worker loop continuously consuming events."""
        while True:
            with self._lock:
                if not self._is_running:
                    break

            event = self.buffer.get()
            if event is None:
                time.sleep(0.05)
                continue

            start_time = time.time()
            self._dispatch_event(event)
            latency_ms = (time.time() - start_time) * 1000.0
            self.metrics.record_event(event, latency_ms=latency_ms)

    def _dispatch_event(self, event: WindowsEventSchema) -> None:
        """Forward event to all active subscriber callbacks."""
        with self._lock:
            subscribers = list(self._subscribers.values())

        for callback in subscribers:
            try:
                callback(event)
            except Exception as exc:
                logger.error(f"Error in subscriber callback: {exc}")
