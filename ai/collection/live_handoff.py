"""Live Event Pipeline Handoff Engine.

Establishes the authoritative boundary between Windows Security Event Log
ingestion (ai/collection/) and downstream processing pipelines.

Provides a thread-safe, bounded handoff engine with backpressure control that
accepts normalized WindowsEventSchema records from LiveWindowsEventReader or
LocalSecurityLogMonitor and delivers them to registered EventConsumer instances.

Phase 2.3 — Live Event Pipeline Handoff Engine
"""

from abc import ABC, abstractmethod
from collections import deque
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from ai.collection.schema import WindowsEventSchema

logger = logging.getLogger("LiveEventHandoffEngine")


class EventConsumer(ABC):
    """Abstract base class contract for downstream event consumers."""

    def __init__(self, consumer_id: Optional[str] = None) -> None:
        """Initialize EventConsumer.

        Args:
            consumer_id: Unique string identifier for consumer.
        """
        self.consumer_id: str = consumer_id or str(uuid.uuid4())

    @abstractmethod
    def consume_event(self, event: WindowsEventSchema) -> bool:
        """Consume a normalized WindowsEventSchema record.

        Args:
            event: The normalized event record.

        Returns:
            True if event was processed successfully, False otherwise.
        """
        pass


class FunctionEventConsumer(EventConsumer):
    """Wraps a python function or callback as an EventConsumer."""

    def __init__(self, callback_fn: Callable[[WindowsEventSchema], Any], consumer_id: Optional[str] = None) -> None:
        """Initialize FunctionEventConsumer.

        Args:
            callback_fn: Callback function taking a WindowsEventSchema instance.
            consumer_id: Optional consumer ID string.
        """
        super().__init__(consumer_id=consumer_id)
        self.callback_fn = callback_fn

    def consume_event(self, event: WindowsEventSchema) -> bool:
        """Invoke wrapped callback function."""
        try:
            res = self.callback_fn(event)
            return bool(res) if res is not None else True
        except Exception as exc:
            logger.error(f"Consumer '{self.consumer_id}' callback error: {exc}")
            return False


class MinimalTestConsumer(EventConsumer):
    """Minimal verification consumer that records and prints received events in order."""

    def __init__(self, consumer_id: str = "minimal_test_consumer") -> None:
        """Initialize MinimalTestConsumer.

        Args:
            consumer_id: Optional string consumer ID.
        """
        super().__init__(consumer_id=consumer_id)
        self.received_events: List[WindowsEventSchema] = []
        self._lock = threading.Lock()

    def consume_event(self, event: WindowsEventSchema) -> bool:
        """Record received WindowsEventSchema in order."""
        with self._lock:
            self.received_events.append(event)
        logger.info(f"[Handoff Consumer] Received RecordID={event.record_id} EventID={event.event_id}")
        return True

    def get_received_record_ids(self) -> List[int]:
        """Return list of received EventRecordIDs in order."""
        with self._lock:
            return [e.record_id for e in self.received_events]

    def print_summary(self) -> None:
        """Print summary of received events to stdout."""
        with self._lock:
            print(f"--- MinimalTestConsumer ({self.consumer_id}) Summary ---")
            print(f"Total Events Received: {len(self.received_events)}")
            for i, evt in enumerate(self.received_events, 1):
                print(f"  [{i}] RecordID={evt.record_id:<8} EventID={evt.event_id:<6} Computer={evt.computer}")


class LiveEventHandoffEngine:
    """Thread-safe handoff coordinator between ingestion and consumers.

    Attributes:
        max_queue_size: Maximum capacity of handoff queue.
        overflow_policy: Policy when queue is full ('drop_oldest', 'drop_newest', 'block').
        total_submitted: Lifetime count of events submitted.
        total_delivered: Lifetime count of events delivered to consumers.
        dropped_count: Lifetime count of dropped events due to overflow.
    """

    def __init__(
        self,
        max_queue_size: int = 1000,
        overflow_policy: str = "drop_oldest",
    ) -> None:
        """Initialize LiveEventHandoffEngine.

        Args:
            max_queue_size: Maximum queue capacity (must be > 0).
            overflow_policy: 'drop_oldest', 'drop_newest', or 'block'.
        """
        if max_queue_size <= 0:
            raise ValueError("max_queue_size must be a positive integer > 0")

        valid_policies = ("drop_oldest", "drop_newest", "block")
        if overflow_policy not in valid_policies:
            raise ValueError(f"Invalid overflow_policy '{overflow_policy}'. Must be one of {valid_policies}")

        self.max_queue_size = max_queue_size
        self.overflow_policy = overflow_policy

        self.total_submitted: int = 0
        self.total_delivered: int = 0
        self.dropped_count: int = 0
        self.delivery_failures: int = 0

        self._queue: deque[WindowsEventSchema] = deque()
        self._consumers: Dict[str, EventConsumer] = {}
        self._lock = threading.Lock()
        self._is_running: bool = False
        self._thread: Optional[threading.Thread] = None

    def register_consumer(self, consumer: EventConsumer) -> str:
        """Register a downstream EventConsumer instance.

        Args:
            consumer: EventConsumer subclass instance.

        Returns:
            Consumer ID string.
        """
        with self._lock:
            self._consumers[consumer.consumer_id] = consumer
        logger.info(f"Registered downstream event consumer: '{consumer.consumer_id}'")
        return consumer.consumer_id

    def register_callback(self, callback_fn: Callable[[WindowsEventSchema], Any], name: Optional[str] = None) -> str:
        """Register a callback function as an event consumer.

        Args:
            callback_fn: Function accepting a WindowsEventSchema.
            name: Optional name for consumer.

        Returns:
            Consumer ID string.
        """
        consumer = FunctionEventConsumer(callback_fn=callback_fn, consumer_id=name)
        return self.register_consumer(consumer)

    def unregister_consumer(self, consumer_id: str) -> bool:
        """Unregister an event consumer.

        Args:
            consumer_id: Consumer ID string.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            if consumer_id in self._consumers:
                del self._consumers[consumer_id]
                logger.info(f"Unregistered downstream event consumer: '{consumer_id}'")
                return True
        return False

    def consumer_count(self) -> int:
        """Return count of active registered consumers."""
        with self._lock:
            return len(self._consumers)

    def submit_event(self, event: WindowsEventSchema) -> bool:
        """Submit a normalized event into the handoff queue.

        Args:
            event: Normalized WindowsEventSchema record.

        Returns:
            True if event was queued successfully, False if dropped due to overflow.
        """
        with self._lock:
            self.total_submitted += 1

            if len(self._queue) >= self.max_queue_size:
                if self.overflow_policy == "drop_oldest":
                    self._queue.popleft()
                    self.dropped_count += 1
                    self._queue.append(event)
                    logger.warning("LiveEventHandoffEngine queue overflow: dropped oldest event.")
                    return True
                elif self.overflow_policy == "drop_newest":
                    self.dropped_count += 1
                    logger.warning("LiveEventHandoffEngine queue overflow: dropped incoming event.")
                    return False
                elif self.overflow_policy == "block":
                    self.dropped_count += 1
                    logger.warning("LiveEventHandoffEngine queue full: rejected incoming event.")
                    return False

            self._queue.append(event)
            return True

    def process_next_event(self) -> bool:
        """Process and deliver the next queued event to all registered consumers.

        Useful for manual ticks, testing, and synchronous handoff.

        Returns:
            True if an event was popped and processed, False if queue was empty.
        """
        with self._lock:
            if not self._queue:
                return False
            event = self._queue.popleft()
            consumers = list(self._consumers.values())

        if not consumers:
            logger.debug("No registered consumers for handoff delivery.")
            return True

        for consumer in consumers:
            success = consumer.consume_event(event)
            with self._lock:
                if success:
                    self.total_delivered += 1
                else:
                    self.delivery_failures += 1

        return True

    def start_handoff(self) -> None:
        """Start background handoff worker thread."""
        with self._lock:
            if self._is_running:
                logger.warning("LiveEventHandoffEngine is already running.")
                return
            self._is_running = True
            self._thread = threading.Thread(
                target=self._handoff_worker_loop, daemon=True, name="LiveEventHandoffThread"
            )
            self._thread.start()
        logger.info("LiveEventHandoffEngine started background worker thread.")

    def stop_handoff(self, timeout: float = 2.0) -> None:
        """Stop background handoff worker thread after draining queued events.

        Args:
            timeout: Maximum seconds to wait for worker thread join.
        """
        # Drain remaining queued events prior to shutdown to prevent event loss
        while self.process_next_event():
            pass

        with self._lock:
            if not self._is_running:
                return
            self._is_running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        logger.info("LiveEventHandoffEngine background thread stopped.")

    def get_handoff_stats(self) -> Dict[str, Any]:
        """Return engine operational status and handoff metrics.

        Returns:
            Dictionary containing queue status, metrics, and consumer info.
        """
        with self._lock:
            q_size = len(self._queue)
            consumer_ids = list(self._consumers.keys())
            is_running = self._is_running

        return {
            "status": "running" if is_running else "stopped",
            "queue_size": q_size,
            "max_queue_size": self.max_queue_size,
            "overflow_policy": self.overflow_policy,
            "total_submitted": self.total_submitted,
            "total_delivered": self.total_delivered,
            "dropped_count": self.dropped_count,
            "delivery_failures": self.delivery_failures,
            "active_consumers": consumer_ids,
        }

    # ──────────────────────────────────────────────────────────
    # Private Worker Loop
    # ──────────────────────────────────────────────────────────

    def _handoff_worker_loop(self) -> None:
        """Background thread worker loop delivering queued events to consumers."""
        while True:
            with self._lock:
                if not self._is_running:
                    break

            processed = self.process_next_event()
            if not processed:
                time.sleep(0.02)


# ──────────────────────────────────────────────────────────────────────────────
# Manual Windows Smoke-Test CLI Entry Point
# Run with:  python -m ai.collection.live_handoff --duration 3.0
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    from ai.collection.live_monitor import LocalSecurityLogMonitor

    parser = argparse.ArgumentParser(description="Live Event Pipeline Handoff Engine Smoke Test")
    parser.add_argument("--duration", type=float, default=3.0, help="Monitoring duration in seconds")
    parser.add_argument("--interval", type=float, default=1.0, help="Polling interval in seconds")
    args = parser.parse_args()

    print("=" * 72)
    print("  Live Event Pipeline Handoff Engine — Phase 2.3 Smoke Test")
    print("=" * 72)
    print(f"  Duration : {args.duration} seconds")
    print(f"  Interval : {args.interval} seconds")
    print()

    monitor = LocalSecurityLogMonitor(poll_interval_sec=args.interval)
    engine = LiveEventHandoffEngine(max_queue_size=1000, overflow_policy="drop_oldest")
    consumer = MinimalTestConsumer(consumer_id="live_security_test_consumer")

    engine.register_consumer(consumer)
    monitor.add_listener(lambda evt: engine.submit_event(evt))

    print("[INFO] Starting continuous monitor & handoff engine...")
    monitor.start_monitoring()
    engine.start_handoff()

    try:
        time.sleep(args.duration)
    except KeyboardInterrupt:
        print("\n[INFO] Smoke test interrupted by user.")

    print("[INFO] Stopping monitor & handoff engine...")
    monitor.stop_monitoring()
    engine.stop_handoff()

    print()
    print("------------------------------------------------------------------------")
    print("  HANDOFF ENGINE REPORT")
    print("------------------------------------------------------------------------")
    stats = engine.get_handoff_stats()
    print(f"  Engine Status      : {stats['status'].upper()}")
    print(f"  Total Submitted    : {stats['total_submitted']}")
    print(f"  Total Delivered    : {stats['total_delivered']}")
    print(f"  Dropped Count      : {stats['dropped_count']}")
    print(f"  Delivery Failures  : {stats['delivery_failures']}")
    print(f"  Active Consumers   : {stats['active_consumers']}")
    print()
    consumer.print_summary()
    print()
    print("=" * 72)
