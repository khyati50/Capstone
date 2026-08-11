"""Real-Time Event Buffer — Thread-Safe Bounded Event Queue.

Provides a thread-safe ring/bounded buffer for live Windows Security Event Log records,
supporting configurable overflow policies (drop_oldest, drop_newest, block) and
metrics tracking.

Phase 2.1 — Windows Real-Time Implementation
"""

from collections import deque
import logging

from threading import Lock
from typing import Any, Dict, Optional, List

from ai.collection.schema import WindowsEventSchema

logger = logging.getLogger("RealTimeEventBuffer")


class RealTimeEventBuffer:
    """Thread-safe bounded event queue for real-time log ingestion.

    Attributes:
        max_size: Maximum capacity of the buffer.
        overflow_policy: Policy when full: 'drop_oldest', 'drop_newest', or 'block'.
        dropped_count: Total count of dropped events due to buffer overflow.
    """

    def __init__(self, max_size: int = 1000, overflow_policy: str = "drop_oldest") -> None:
        """Initialize RealTimeEventBuffer.

        Args:
            max_size: Maximum capacity of the buffer (must be > 0).
            overflow_policy: 'drop_oldest', 'drop_newest', or 'block'.

        Raises:
            ValueError: If max_size <= 0 or overflow_policy is invalid.
        """
        if max_size <= 0:
            raise ValueError("max_size must be a positive integer > 0")

        valid_policies = ("drop_oldest", "drop_newest", "block")
        if overflow_policy not in valid_policies:
            raise ValueError(f"Invalid overflow_policy '{overflow_policy}'. Must be one of {valid_policies}")

        self.max_size = max_size
        self.overflow_policy = overflow_policy
        self.dropped_count: int = 0
        self._buffer: deque[WindowsEventSchema] = deque()
        self._lock = Lock()

    def put(self, event: WindowsEventSchema) -> bool:
        """Push a normalized event into the buffer.

        Args:
            event: Normalized WindowsEventSchema record.

        Returns:
            True if event was successfully added, False if dropped due to overflow.
        """
        with self._lock:
            if len(self._buffer) >= self.max_size:
                if self.overflow_policy == "drop_oldest":
                    self._buffer.popleft()
                    self.dropped_count += 1
                    self._buffer.append(event)
                    logger.warning("RealTimeEventBuffer overflow: dropped oldest event.")
                    return True
                elif self.overflow_policy == "drop_newest":
                    self.dropped_count += 1
                    logger.warning("RealTimeEventBuffer overflow: dropped newest incoming event.")
                    return False
                elif self.overflow_policy == "block":
                    # Non-blocking return False for real-time buffer safety
                    self.dropped_count += 1
                    logger.warning("RealTimeEventBuffer full (block policy): rejected incoming event.")
                    return False

            self._buffer.append(event)
            return True

    def get(self) -> Optional[WindowsEventSchema]:
        """Pop and return the oldest event from the buffer.

        Returns:
            Oldest WindowsEventSchema if buffer non-empty, None if empty.
        """
        with self._lock:
            if not self._buffer:
                return None
            return self._buffer.popleft()

    def peek(self) -> Optional[WindowsEventSchema]:
        """Inspect the oldest event without removing it.

        Returns:
            Oldest WindowsEventSchema if buffer non-empty, None if empty.
        """
        with self._lock:
            if not self._buffer:
                return None
            return self._buffer[0]

    def clear(self) -> int:
        """Empty the buffer and return count of cleared events.

        Returns:
            Number of events removed.
        """
        with self._lock:
            cleared = len(self._buffer)
            self._buffer.clear()
            return cleared

    def size(self) -> int:
        """Return current number of events in the buffer."""
        with self._lock:
            return len(self._buffer)

    def fill_percentage(self) -> float:
        """Return buffer fill percentage (0.0 to 100.0)."""
        with self._lock:
            return round((len(self._buffer) / self.max_size) * 100.0, 2)

    def get_all(self) -> List[WindowsEventSchema]:
        """Drain and return all events currently in the buffer."""
        with self._lock:
            events = list(self._buffer)
            self._buffer.clear()
            return events

    def get_status(self) -> Dict[str, Any]:
        """Return status and utilization summary dictionary."""
        with self._lock:
            return {
                "max_size": self.max_size,
                "current_size": len(self._buffer),
                "fill_percentage": round((len(self._buffer) / self.max_size) * 100.0, 2),
                "overflow_policy": self.overflow_policy,
                "dropped_count": self.dropped_count,
            }
