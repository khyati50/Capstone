"""Unit Tests — Phase 2.3: Live Event Pipeline Handoff Engine.

Tests the handoff boundary engine:
  - LiveEventHandoffEngine queue initialization, bounded capacity, and overflow policies
  - EventConsumer abstract base class and FunctionEventConsumer wrapper
  - Consumer registration, submission, and delivery handshake
  - Background worker thread handoff delivery
  - Exception handling in consumer callbacks
  - Engine status and metric statistics

Phase 2.3 — Live Event Pipeline Handoff Engine
"""

import time
from typing import List
import pytest

from ai.collection.live_handoff import EventConsumer, FunctionEventConsumer, LiveEventHandoffEngine
from ai.collection.schema import WindowsEventSchema


# ─────────────────────────────────────────────────────────────────────────────
# Test Fixtures & Stub Consumer
# ─────────────────────────────────────────────────────────────────────────────


def _make_event(event_id: int = 4625, record_id: int = 101) -> WindowsEventSchema:
    """Helper fixture to construct WindowsEventSchema objects."""
    return WindowsEventSchema(
        event_id=event_id,
        record_id=record_id,
        timestamp="2026-08-11T11:00:00Z",
        computer="TEST-DC01",
        channel="Security",
        target_user="administrator",
    )


class StubConsumer(EventConsumer):
    """Concrete EventConsumer subclass for testing."""

    def __init__(self, consumer_id: str = "stub_1") -> None:
        super().__init__(consumer_id=consumer_id)
        self.received_events: List[WindowsEventSchema] = []

    def consume_event(self, event: WindowsEventSchema) -> bool:
        self.received_events.append(event)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# 1. LiveEventHandoffEngine Tests
# ─────────────────────────────────────────────────────────────────────────────


class TestLiveEventHandoffEngine:
    """Tests for LiveEventHandoffEngine class."""

    def test_engine_initialization(self) -> None:
        """Engine initializes with correct capacity and empty stats."""
        engine = LiveEventHandoffEngine(max_queue_size=100, overflow_policy="drop_oldest")
        assert engine.max_queue_size == 100
        assert engine.overflow_policy == "drop_oldest"
        assert engine.total_submitted == 0
        assert engine.total_delivered == 0
        assert engine.dropped_count == 0
        assert engine.consumer_count() == 0

    def test_invalid_capacity_or_policy_raises(self) -> None:
        """Engine raises ValueError for invalid queue size or policy."""
        with pytest.raises(ValueError, match="max_queue_size must be a positive integer"):
            LiveEventHandoffEngine(max_queue_size=0)

        with pytest.raises(ValueError, match="Invalid overflow_policy"):
            LiveEventHandoffEngine(max_queue_size=10, overflow_policy="invalid_policy")

    def test_register_and_unregister_consumer(self) -> None:
        """Consumers can be registered and unregistered."""
        engine = LiveEventHandoffEngine()
        stub = StubConsumer(consumer_id="consumer_a")

        cid = engine.register_consumer(stub)
        assert cid == "consumer_a"
        assert engine.consumer_count() == 1

        assert engine.unregister_consumer("consumer_a") is True
        assert engine.consumer_count() == 0

    def test_register_callback(self) -> None:
        """Functions can be registered via register_callback."""
        engine = LiveEventHandoffEngine()
        received: List[WindowsEventSchema] = []

        cid = engine.register_callback(lambda e: received.append(e), name="func_consumer")
        assert cid == "func_consumer"
        assert engine.consumer_count() == 1

    def test_submit_and_process_single_event(self) -> None:
        """submit_event queues event and process_next_event delivers to consumer."""
        engine = LiveEventHandoffEngine(max_queue_size=10)
        stub = StubConsumer(consumer_id="stub_consumer")
        engine.register_consumer(stub)

        evt = _make_event(event_id=4625, record_id=1001)
        assert engine.submit_event(evt) is True
        assert engine.total_submitted == 1

        processed = engine.process_next_event()
        assert processed is True
        assert len(stub.received_events) == 1
        assert stub.received_events[0].record_id == 1001
        assert engine.total_delivered == 1

    def test_overflow_policy_drop_oldest(self) -> None:
        """drop_oldest policy drops the oldest queued event when full."""
        engine = LiveEventHandoffEngine(max_queue_size=2, overflow_policy="drop_oldest")
        evt1 = _make_event(record_id=1)
        evt2 = _make_event(record_id=2)
        evt3 = _make_event(record_id=3)

        engine.submit_event(evt1)
        engine.submit_event(evt2)
        assert engine.submit_event(evt3) is True  # Overflow occurs, evt1 dropped

        assert engine.dropped_count == 1

        stub = StubConsumer()
        engine.register_consumer(stub)
        engine.process_next_event()

        assert stub.received_events[0].record_id == 2  # evt1 was dropped, evt2 is popped

    def test_overflow_policy_drop_newest(self) -> None:
        """drop_newest policy rejects incoming event when full."""
        engine = LiveEventHandoffEngine(max_queue_size=2, overflow_policy="drop_newest")
        evt1 = _make_event(record_id=1)
        evt2 = _make_event(record_id=2)
        evt3 = _make_event(record_id=3)

        engine.submit_event(evt1)
        engine.submit_event(evt2)
        assert engine.submit_event(evt3) is False  # Rejected

        assert engine.dropped_count == 1

        stub = StubConsumer()
        engine.register_consumer(stub)
        engine.process_next_event()

        assert stub.received_events[0].record_id == 1  # evt1 preserved

    def test_background_worker_thread_handoff(self) -> None:
        """Background thread continuously delivers queued events to consumers."""
        engine = LiveEventHandoffEngine(max_queue_size=50)
        stub = StubConsumer()
        engine.register_consumer(stub)

        engine.start_handoff()
        assert engine.get_handoff_stats()["status"] == "running"

        engine.submit_event(_make_event(record_id=201))
        engine.submit_event(_make_event(record_id=202))

        time.sleep(0.1)  # Wait for worker thread processing

        engine.stop_handoff()
        assert engine.get_handoff_stats()["status"] == "stopped"
        assert len(stub.received_events) == 2
        assert stub.received_events[0].record_id == 201
        assert stub.received_events[1].record_id == 202

    def test_consumer_exception_handling(self) -> None:
        """Consumer callback throwing exception is caught without breaking engine."""
        engine = LiveEventHandoffEngine()

        def _faulty_consumer(evt: WindowsEventSchema) -> None:
            raise RuntimeError("Consumer crash simulation")

        engine.register_callback(_faulty_consumer, name="bad_consumer")
        engine.submit_event(_make_event())

        # Processing should complete without raising exception
        assert engine.process_next_event() is True
        assert engine.delivery_failures == 1

    def test_get_handoff_stats(self) -> None:
        """get_handoff_stats returns complete metrics dictionary."""
        engine = LiveEventHandoffEngine(max_queue_size=20)
        stats = engine.get_handoff_stats()

        assert stats["status"] == "stopped"
        assert stats["max_queue_size"] == 20
        assert stats["total_submitted"] == 0
        assert stats["total_delivered"] == 0
        assert stats["dropped_count"] == 0
        assert "active_consumers" in stats

    def test_failed_downstream_handoff_does_not_corrupt_checkpoint(self) -> None:
        """A failed downstream consumer handoff does not corrupt or roll back reader checkpoint."""
        from ai.collection.live_reader import LiveWindowsEventReader

        reader = LiveWindowsEventReader(channel="Security")
        reader.last_record_id = 1000

        engine = LiveEventHandoffEngine()

        def _crashing_consumer(evt: WindowsEventSchema) -> bool:
            raise ValueError("Downstream processing failure")

        engine.register_callback(_crashing_consumer, name="crash_consumer")
        evt = _make_event(record_id=1005)

        engine.submit_event(evt)
        engine.process_next_event()

        # Checkpoint on reader remains intact at 1000 (uncorrupted)
        assert reader.last_record_id == 1000
        assert engine.delivery_failures == 1


    def test_minimal_test_consumer_receives_multiple_events_in_order(self) -> None:
        """MinimalTestConsumer receives and records multiple events in exact sequential order."""
        from ai.collection import MinimalTestConsumer

        engine = LiveEventHandoffEngine(max_queue_size=50)
        consumer = MinimalTestConsumer(consumer_id="verify_consumer")
        engine.register_consumer(consumer)

        events = [
            _make_event(event_id=4625, record_id=101),
            _make_event(event_id=4688, record_id=102),
            _make_event(event_id=4672, record_id=103),
            _make_event(event_id=4720, record_id=104),
        ]

        for evt in events:
            engine.submit_event(evt)

        # Process all submitted events
        while engine.process_next_event():
            pass

        assert consumer.get_received_record_ids() == [101, 102, 103, 104]
        assert len(consumer.received_events) == 4
        consumer.print_summary()

    def test_shutdown_does_not_lose_accepted_events(self) -> None:
        """Shutdown of background worker delivers already accepted events."""
        engine = LiveEventHandoffEngine(max_queue_size=50)
        stub = StubConsumer()
        engine.register_consumer(stub)

        engine.submit_event(_make_event(record_id=501))
        engine.submit_event(_make_event(record_id=502))

        # Start worker and immediately stop
        engine.start_handoff()
        engine.stop_handoff(timeout=2.0)

        # Ensure all queued events were delivered prior to shutdown
        assert len(stub.received_events) == 2
        assert [e.record_id for e in stub.received_events] == [501, 502]

    def test_package_exports(self) -> None:
        """Handoff components are exportable from ai.collection."""
        from ai.collection import LiveEventHandoffEngine as Engine, EventConsumer as Consumer

        e = Engine()
        assert e.max_queue_size == 1000
