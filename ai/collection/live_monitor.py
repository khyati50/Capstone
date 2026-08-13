"""Continuous Local Windows Security Event Log Monitor.

Provides the LocalSecurityLogMonitor class for non-blocking continuous background
monitoring of the local Windows Security Event Log ('Security' channel only).

Integrates with LiveWindowsEventReader and EventRecordID checkpointing to poll
new unread records on a background daemon thread, dispatching normalized
WindowsEventSchema records to registered listener callbacks.

Phase 2.2 — Continuous Local Windows Security Event Monitoring
"""

import logging
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from ai.collection.live_reader import LiveWindowsEventReader
from ai.collection.schema import WindowsEventSchema

logger = logging.getLogger("LocalSecurityLogMonitor")

# Callback function type signature for event listeners
EventListener = Callable[[WindowsEventSchema], None]


class LocalSecurityLogMonitor:
    """Non-blocking background manager for continuous local Security Event Log monitoring.

    Scoped strictly to the local 'Security' log channel. Runs a polling loop on a
    dedicated background daemon thread, maintaining checkpoint deduplication via
    LiveWindowsEventReader.last_record_id.

    Attributes:
        poll_interval_sec: Seconds to wait between polling ticks.
        reader: LiveWindowsEventReader instance.
        state: Current operational state ('STOPPED', 'RUNNING', 'PAUSED', 'ERROR').
    """

    def __init__(
        self,
        poll_interval_sec: float = 1.0,
        reader: Optional[LiveWindowsEventReader] = None,
    ) -> None:
        """Initialize LocalSecurityLogMonitor.

        Args:
            poll_interval_sec: Polling interval in seconds (must be > 0).
            reader: Optional LiveWindowsEventReader instance (default creates new Security reader).
        """
        if poll_interval_sec <= 0:
            raise ValueError("poll_interval_sec must be a positive float > 0")

        self.poll_interval_sec = poll_interval_sec
        self.reader = reader or LiveWindowsEventReader(channel="Security")
        self.state: str = "STOPPED"

        self.total_polls: int = 0
        self.total_events_emitted: int = 0
        self.last_poll_timestamp: Optional[str] = None
        self.last_error: Optional[str] = None

        self._listeners: Dict[str, EventListener] = {}
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None

    def add_listener(self, callback_fn: EventListener) -> str:
        """Register a callback listener to receive new WindowsEventSchema objects.

        Args:
            callback_fn: Callback taking a WindowsEventSchema instance.

        Returns:
            Unique listener ID string.
        """
        listener_id = str(uuid.uuid4())
        with self._lock:
            self._listeners[listener_id] = callback_fn
        logger.info(f"Registered Security Log monitor listener: {listener_id}")
        return listener_id

    def remove_listener(self, listener_id: str) -> bool:
        """Unregister an event listener.

        Args:
            listener_id: Listener ID string returned by add_listener.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            if listener_id in self._listeners:
                del self._listeners[listener_id]
                logger.info(f"Removed Security Log monitor listener: {listener_id}")
                return True
        return False

    def listener_count(self) -> int:
        """Return count of registered listeners."""
        with self._lock:
            return len(self._listeners)

    def start_monitoring(self) -> None:
        """Start non-blocking background polling worker thread."""
        with self._lock:
            if self.state in ("RUNNING", "PAUSED"):
                logger.warning(f"LocalSecurityLogMonitor is already in state '{self.state}'.")
                return

            self.state = "RUNNING"
            self._thread = threading.Thread(
                target=self._monitor_worker_loop,
                daemon=True,
                name="LocalSecurityLogMonitorThread",
            )
            self._thread.start()

        logger.info(f"LocalSecurityLogMonitor started background polling thread (interval={self.poll_interval_sec}s).")

    def stop_monitoring(self, timeout: float = 2.0) -> None:
        """Stop background monitoring worker thread.

        Args:
            timeout: Maximum seconds to wait for worker thread join.
        """
        with self._lock:
            if self.state == "STOPPED":
                return
            self.state = "STOPPED"

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

        logger.info("LocalSecurityLogMonitor background thread stopped.")

    def pause_monitoring(self) -> None:
        """Pause continuous polling without stopping the worker thread."""
        with self._lock:
            if self.state == "RUNNING":
                self.state = "PAUSED"
                logger.info("LocalSecurityLogMonitor paused.")

    def resume_monitoring(self) -> None:
        """Resume continuous polling from PAUSED state."""
        with self._lock:
            if self.state == "PAUSED":
                self.state = "RUNNING"
                logger.info("LocalSecurityLogMonitor resumed.")

    def poll_once(self, batch_size: int = 50) -> List[WindowsEventSchema]:
        """Perform a single polling tick against the Security Event Log.

        Useful for manual ticks, testing, and explicit single-shot polling.

        Args:
            batch_size: Maximum events to query.

        Returns:
            List of newly acquired, non-duplicate WindowsEventSchema objects.
        """
        self.total_polls += 1
        self.last_poll_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            new_events = self.reader.read_new_events(max_records=batch_size)
        except Exception as exc:
            self.last_error = str(exc)
            logger.error(f"Error during Security log poll_once tick: {exc}")
            return []

        if new_events:
            self.total_events_emitted += len(new_events)
            self._dispatch_events(new_events)

        return new_events

    def get_monitor_status(self) -> Dict[str, Any]:
        """Return monitor operational state and performance statistics.

        Returns:
            Dictionary containing state, poll counts, listener count, reader status.
        """
        with self._lock:
            current_state = self.state

        reader_status = self.reader.get_reader_status()
        return {
            "state": current_state,
            "channel": self.reader.channel,
            "poll_interval_sec": self.poll_interval_sec,
            "total_polls": self.total_polls,
            "total_events_emitted": self.total_events_emitted,
            "last_poll_timestamp": self.last_poll_timestamp,
            "last_error": self.last_error,
            "listener_count": self.listener_count(),
            "reader": reader_status,
        }

    # ──────────────────────────────────────────────────────────
    # Private Worker & Dispatch Implementation
    # ──────────────────────────────────────────────────────────

    def _monitor_worker_loop(self) -> None:
        """Background thread worker loop executing periodic polling ticks."""
        while True:
            with self._lock:
                if self.state == "STOPPED":
                    break
                current_state = self.state

            if current_state == "RUNNING":
                self.poll_once(batch_size=50)

            time.sleep(self.poll_interval_sec)

    def _dispatch_events(self, events: List[WindowsEventSchema]) -> None:
        """Forward new events to all registered listener callbacks."""
        with self._lock:
            listeners = list(self._listeners.values())

        for event in events:
            for callback in listeners:
                try:
                    callback(event)
                except Exception as exc:
                    logger.error(f"Error in monitor listener callback: {exc}")


# ──────────────────────────────────────────────────────────────────────────────
# Manual Windows Smoke Test CLI Entry Point
# Run with:  python -m ai.collection.live_monitor [--duration 10]
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m ai.collection.live_monitor",
        description="Phase 2.2 Local Windows Security Event Log Continuous Monitoring Smoke Test",
    )
    parser.add_argument(
        "--duration",
        "-d",
        type=float,
        default=5.0,
        help="Seconds to run continuous background monitoring before stopping (default: 5.0)",
    )
    parser.add_argument(
        "--interval",
        "-i",
        type=float,
        default=1.0,
        help="Polling interval in seconds (default: 1.0)",
    )

    args = parser.parse_args()

    print("=" * 72)
    print("  Continuous Local Windows Security Event Log Monitor — Smoke Test")
    print("=" * 72)
    print(f"  Duration : {args.duration} seconds")
    print(f"  Interval : {args.interval} seconds")
    print()

    received_events: List[WindowsEventSchema] = []

    def _on_new_event(evt: WindowsEventSchema) -> None:
        received_events.append(evt)
        print(
            f"  [LIVE EVENT] RecordID={evt.record_id:<8} "
            f"EventID={evt.event_id:<6} "
            f"Computer={evt.computer:<20} "
            f"User={evt.target_user or evt.subject_user}"
        )

    monitor = LocalSecurityLogMonitor(poll_interval_sec=args.interval)
    monitor.add_listener(_on_new_event)

    print("[INFO] Starting continuous monitoring thread...")
    monitor.start_monitoring()

    time.sleep(args.duration)

    print("[INFO] Stopping monitoring thread...")
    monitor.stop_monitoring()

    status = monitor.get_monitor_status()

    print()
    print("------------------------------------------------------------------------")
    print("  MONITORING SUMMARY REPORT")
    print("------------------------------------------------------------------------")
    print(f"  State                : {status['state']}")
    print(f"  Total Poll Ticks     : {status['total_polls']}")
    print(f"  Total Events Emitted : {status['total_events_emitted']}")
    print(f"  Checkpoint RecordID  : {status['reader']['last_record_id']}")
    print(f"  Last Poll Timestamp  : {status['last_poll_timestamp']}")
    print(f"  Events Captured      : {len(received_events)}")
    print()
    print("=" * 72)
