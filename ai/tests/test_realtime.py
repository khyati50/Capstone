"""Unit Tests — Phase 2.1: Windows Real-Time Implementation.

Tests the complete ai/realtime/ package:
  - RealTimeEventBuffer thread safety, capacity limits, and overflow policies
  - StreamMetricsCalculator EPS, peak EPS, latency, and window purging
  - StreamProducers (FileTailProducer, WinEvtLogProducer, SyntheticStreamProducer)
  - RealTimeStreamListener background worker, subscriber callbacks, and lifecycle

Phase 2.1 — Windows Real-Time Implementation
"""

import json
import tempfile
import time
from pathlib import Path

import pytest

from ai.collection.schema import WindowsEventSchema
from ai.realtime import (
    RealTimeEventBuffer,
    StreamMetricsCalculator,
    RealTimeStreamListener,
    FileTailProducer,
    WinEvtLogProducer,
    SyntheticStreamProducer,
)


# ─────────────────────────────────────────────────────────────────────────────
# 1. RealTimeEventBuffer Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestRealTimeEventBuffer:
    """Tests for RealTimeEventBuffer class."""

    def test_buffer_initialization(self) -> None:
        """Buffer initializes with correct size and empty state."""
        buf = RealTimeEventBuffer(max_size=100, overflow_policy="drop_oldest")
        assert buf.size() == 0
        assert buf.fill_percentage() == 0.0
        assert buf.dropped_count == 0

    def test_invalid_buffer_initialization(self) -> None:
        """Buffer raises ValueError for invalid max_size or policy."""
        with pytest.raises(ValueError):
            RealTimeEventBuffer(max_size=0)

        with pytest.raises(ValueError):
            RealTimeEventBuffer(max_size=10, overflow_policy="invalid_policy")

    def test_put_and_get_single_event(self) -> None:
        """Event can be pushed to and popped from buffer."""
        buf = RealTimeEventBuffer(max_size=10)
        evt = WindowsEventSchema(event_id=4625, computer="DC-01")

        assert buf.put(evt) is True
        assert buf.size() == 1
        assert buf.fill_percentage() == 10.0

        popped = buf.get()
        assert popped is not None
        assert popped.event_id == 4625
        assert buf.size() == 0

    def test_peek_does_not_remove_event(self) -> None:
        """Peek returns the event without removing it."""
        buf = RealTimeEventBuffer(max_size=10)
        evt = WindowsEventSchema(event_id=4688, computer="HOST-1")
        buf.put(evt)

        peeked = buf.peek()
        assert peeked is not None
        assert peeked.event_id == 4688
        assert buf.size() == 1

    def test_overflow_policy_drop_oldest(self) -> None:
        """drop_oldest policy drops the oldest event when full."""
        buf = RealTimeEventBuffer(max_size=2, overflow_policy="drop_oldest")
        evt1 = WindowsEventSchema(event_id=1, computer="HOST-1")
        evt2 = WindowsEventSchema(event_id=2, computer="HOST-2")
        evt3 = WindowsEventSchema(event_id=3, computer="HOST-3")

        buf.put(evt1)
        buf.put(evt2)
        assert buf.put(evt3) is True  # Overflow occurs, evt1 dropped

        assert buf.size() == 2
        assert buf.dropped_count == 1

        popped = buf.get()
        assert popped is not None
        assert popped.event_id == 2  # evt1 was dropped, so evt2 is first

    def test_overflow_policy_drop_newest(self) -> None:
        """drop_newest policy rejects incoming event when full."""
        buf = RealTimeEventBuffer(max_size=2, overflow_policy="drop_newest")
        evt1 = WindowsEventSchema(event_id=1)
        evt2 = WindowsEventSchema(event_id=2)
        evt3 = WindowsEventSchema(event_id=3)

        buf.put(evt1)
        buf.put(evt2)
        assert buf.put(evt3) is False  # Rejected

        assert buf.size() == 2
        assert buf.dropped_count == 1
        assert buf.get().event_id == 1  # evt1 preserved

    def test_clear_buffer(self) -> None:
        """Clear empties the buffer and returns count."""
        buf = RealTimeEventBuffer(max_size=10)
        buf.put(WindowsEventSchema(event_id=4625))
        buf.put(WindowsEventSchema(event_id=4688))

        cleared = buf.clear()
        assert cleared == 2
        assert buf.size() == 0

    def test_get_all(self) -> None:
        """get_all drains all events at once."""
        buf = RealTimeEventBuffer(max_size=10)
        buf.put(WindowsEventSchema(event_id=1))
        buf.put(WindowsEventSchema(event_id=2))

        all_evts = buf.get_all()
        assert len(all_evts) == 2
        assert buf.size() == 0

    def test_get_status(self) -> None:
        """get_status returns accurate summary dict."""
        buf = RealTimeEventBuffer(max_size=5)
        buf.put(WindowsEventSchema(event_id=4624))

        status = buf.get_status()
        assert status["max_size"] == 5
        assert status["current_size"] == 1
        assert status["fill_percentage"] == 20.0
        assert status["dropped_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# 2. StreamMetricsCalculator Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestStreamMetricsCalculator:
    """Tests for StreamMetricsCalculator class."""

    def test_initial_metrics_zero(self) -> None:
        """Metrics start at 0."""
        calc = StreamMetricsCalculator(window_seconds=5.0)
        summary = calc.get_metrics_summary()
        assert summary["current_eps"] == 0.0
        assert summary["total_events_processed"] == 0
        assert summary["average_latency_ms"] == 0.0

    def test_record_event_calculates_eps(self) -> None:
        """Recording events updates total count and EPS."""
        calc = StreamMetricsCalculator(window_seconds=2.0)
        evt = WindowsEventSchema(event_id=4625)

        for _ in range(4):
            calc.record_event(evt, latency_ms=10.0)

        assert calc.total_events_processed == 4
        assert calc.get_current_eps() > 0.0
        assert calc.get_average_latency_ms() == 10.0

    def test_reset_metrics(self) -> None:
        """Reset clears all recorded metrics."""
        calc = StreamMetricsCalculator()
        calc.record_event(WindowsEventSchema(event_id=4624), latency_ms=5.0)
        calc.reset()

        assert calc.total_events_processed == 0
        assert calc.get_current_eps() == 0.0
        assert calc.peak_eps == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# 3. StreamProducers Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestStreamProducers:
    """Tests for SyntheticStreamProducer, FileTailProducer, and WinEvtLogProducer."""

    def test_synthetic_stream_producer(self) -> None:
        """SyntheticStreamProducer generates synthetic events into buffer."""
        buf = RealTimeEventBuffer(max_size=50)
        producer = SyntheticStreamProducer(buf, rate_per_sec=0.0)  # No delay for test
        producer.start()

        evt = producer.produce_next()
        assert evt is not None
        assert evt.is_monitored_event() is True
        assert buf.size() == 1

        producer.stop()
        assert producer.is_active is False

    def test_win_evt_log_producer(self) -> None:
        """WinEvtLogProducer handles live/fallback log generation."""
        buf = RealTimeEventBuffer(max_size=10)
        producer = WinEvtLogProducer(buf, channel="Security")
        producer.start()

        evt = producer.produce_next()
        assert evt is not None
        assert evt.channel == "Security"
        assert buf.size() == 1

        producer.stop()

    def test_file_tail_producer(self) -> None:
        """FileTailProducer reads new JSON line from tailed file."""
        buf = RealTimeEventBuffer(max_size=10)
        record = {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Test"}},
                    "EventID": 4625,
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-08-07T00:00:00Z"}},
                    "Computer": "TAIL-HOST",
                },
                "EventData": {"TargetUserName": "admin"},
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(record, fh)
            fh.write("\n")
            tmp_path = Path(fh.name)

        producer = FileTailProducer(tmp_path, buf)
        producer.start()

        evt = producer.produce_next()
        tmp_path.unlink(missing_ok=True)

        assert evt is not None
        assert evt.event_id == 4625
        assert evt.computer == "TAIL-HOST"
        assert buf.size() == 1

        producer.stop()


# ─────────────────────────────────────────────────────────────────────────────
# 4. RealTimeStreamListener Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestRealTimeStreamListener:
    """Tests for RealTimeStreamListener background dispatcher."""

    def test_listener_subscription(self) -> None:
        """Subscribing and unsubscribing callbacks works correctly."""
        listener = RealTimeStreamListener()
        received: list[WindowsEventSchema] = []

        sub_id = listener.subscribe(lambda evt: received.append(evt))
        assert listener.subscriber_count() == 1

        assert listener.unsubscribe(sub_id) is True
        assert listener.subscriber_count() == 0

    def test_process_next_dispatches_to_subscriber(self) -> None:
        """process_next manually pops buffer and dispatches to subscriber."""
        buf = RealTimeEventBuffer(max_size=10)
        listener = RealTimeStreamListener(buffer=buf)
        received: list[WindowsEventSchema] = []

        listener.subscribe(lambda evt: received.append(evt))

        buf.put(WindowsEventSchema(event_id=4688, computer="DISPATCH-1"))
        dispatched = listener.process_next()

        assert dispatched is not None
        assert dispatched.event_id == 4688
        assert len(received) == 1
        assert received[0].computer == "DISPATCH-1"

    def test_background_listener_worker_thread(self) -> None:
        """Listener worker thread runs in background and dispatches events."""
        buf = RealTimeEventBuffer(max_size=100)
        listener = RealTimeStreamListener(buffer=buf)
        received: list[WindowsEventSchema] = []

        listener.subscribe(lambda evt: received.append(evt))
        listener.start_listening()
        assert listener.is_running() is True

        # Push events into buffer
        buf.put(WindowsEventSchema(event_id=4625, computer="BG-HOST-1"))
        buf.put(WindowsEventSchema(event_id=4672, computer="BG-HOST-2"))

        # Wait briefly for background thread processing
        time.sleep(0.2)

        listener.stop_listening()
        assert listener.is_running() is False
        assert len(received) == 2
        assert received[0].event_id == 4625
        assert received[1].event_id == 4672

    def test_listener_get_status(self) -> None:
        """get_status returns combined status dictionary."""
        listener = RealTimeStreamListener()
        status = listener.get_status()

        assert "status" in status
        assert "subscriber_count" in status
        assert "buffer" in status
        assert "metrics" in status
        assert status["status"] == "stopped"
