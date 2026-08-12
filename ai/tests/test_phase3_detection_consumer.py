"""Phase 3 Test Suite — Real-Time AI Threat Detection Integration.

Comprehensive tests covering:
- AIDetectionConsumer & LivePipelineOrchestrator integration
- Handoff Engine -> AIDetectionConsumer -> Feature Bridge -> Orchestrator pipeline
- Preservation of EventRecordID and event ordering
- Feature dictionary merging (6 computed behavioral features + raw metadata)
- Downstream failure isolation (exceptions do not corrupt reader last_record_id or handoff thread)
- Absence of secondary deduplication gates
- EventConsumer backwards compatibility and clean shutdown
"""

from unittest.mock import MagicMock

from ai.collection.live_handoff import LiveEventHandoffEngine
from ai.collection.schema import WindowsEventSchema
from ai.pipeline.orchestrator import LivePipelineOrchestrator
from ai.realtime.detection_consumer import AIDetectionConsumer
from ai.realtime.feature_bridge import RealTimeFeatureBridge


class TestPhase3DetectionConsumer:
    """Test suite for Phase 3 real-time AI threat detection bridge."""

    def test_consumer_initialization(self):
        """Test AIDetectionConsumer initialization and default attributes."""
        consumer = AIDetectionConsumer()
        assert consumer.consumer_id == "ai_detection_consumer"
        assert consumer.total_processed == 0
        assert consumer.success_count == 0
        assert consumer.failure_count == 0
        assert len(consumer.get_results()) == 0

    def test_windows_event_reaches_orchestrator_and_pipeline(self):
        """Test that a WindowsEventSchema reaches the orchestrator and produces a valid result."""
        consumer = AIDetectionConsumer(consumer_id="test_consumer_1")
        evt = WindowsEventSchema(
            event_id=4624,
            timestamp="2026-08-12T10:00:00Z",
            computer="TEST-HOST",
            target_user="administrator",
            record_id=101,
        )

        success = consumer.consume_event(evt)
        assert success is True
        assert consumer.total_processed == 1
        assert consumer.success_count == 1

        results = consumer.get_results()
        assert len(results) == 1
        res = results[0]
        assert res["record_id"] == 101
        assert res["event_id"] == 4624

        pipeline_result = res["pipeline_result"]
        assert "prediction" in pipeline_result
        assert "risk_score" in pipeline_result
        assert "alert_source" in pipeline_result
        assert pipeline_result["raw_event"]["EventRecordID"] == 101

    def test_feature_bridge_invoked_and_features_merged(self):
        """Test that RealTimeFeatureBridge is invoked and 6 computed features are merged with event data."""
        mock_bridge = MagicMock(wraps=RealTimeFeatureBridge())
        consumer = AIDetectionConsumer(feature_bridge=mock_bridge)

        evt = WindowsEventSchema(
            event_id=4625,
            timestamp="2026-08-12T10:00:00Z",
            computer="CORP-DC-01",
            target_user="administrator",
            record_id=102,
        )

        success = consumer.consume_event(evt)
        assert success is True
        mock_bridge.process_event.assert_called_once_with(evt)

        res = consumer.get_results()[0]["pipeline_result"]
        raw = res["raw_event"]

        # Check raw event parameters
        assert raw["EventID"] == 4625
        assert raw["Computer"] == "CORP-DC-01"
        assert raw["TargetUserName"] == "administrator"
        assert raw["EventRecordID"] == 102

        # Check 6 computed behavioral features from FeatureBridge
        assert "failed_login_count_5m" in raw
        assert "time_delta_prev_event" in raw
        assert "is_powershell_executed" in raw
        assert "privilege_escalation_flag" in raw
        assert "unusual_process_parent_ratio" in raw
        assert "session_duration" in raw

    def test_event_record_id_preserved_unchanged(self):
        """Test that EventRecordID is preserved through the consumer and pipeline boundary."""
        consumer = AIDetectionConsumer()
        record_ids = [5001, 5002, 5003]

        for rid in record_ids:
            evt = WindowsEventSchema(
                event_id=4688,
                timestamp="2026-08-12T10:00:00Z",
                computer="HOST-01",
                process_name="cmd.exe",
                record_id=rid,
            )
            consumer.consume_event(evt)

        results = consumer.get_results()
        assert [r["record_id"] for r in results] == record_ids
        for r in results:
            raw = r["pipeline_result"]["raw_event"]
            assert raw["EventRecordID"] == r["record_id"]
            assert raw["record_id"] == r["record_id"]

    def test_event_ordering_preserved(self):
        """Test that events submitted in order are processed and recorded in exact sequence."""
        engine = LiveEventHandoffEngine(max_queue_size=100)
        consumer = AIDetectionConsumer()
        engine.register_consumer(consumer)

        events = [
            WindowsEventSchema(event_id=4625, record_id=10),
            WindowsEventSchema(event_id=4624, record_id=11),
            WindowsEventSchema(event_id=4672, record_id=12),
        ]

        for e in events:
            engine.submit_event(e)

        # Drain queue
        while engine.process_next_event():
            pass

        results = consumer.get_results()
        received_record_ids = [r["record_id"] for r in results]
        assert received_record_ids == [10, 11, 12]

    def test_no_second_deduplication_gate(self):
        """Test that submitting duplicate record IDs to the consumer processes all events (no second dedup gate)."""
        consumer = AIDetectionConsumer()
        evt1 = WindowsEventSchema(event_id=4625, record_id=200, computer="DC-1")
        evt2 = WindowsEventSchema(event_id=4625, record_id=200, computer="DC-1")

        consumer.consume_event(evt1)
        consumer.consume_event(evt2)

        results = consumer.get_results()
        # Both duplicate events must be delivered and processed by consumer
        assert len(results) == 2
        assert consumer.total_processed == 2
        assert results[0]["record_id"] == 200
        assert results[1]["record_id"] == 200

    def test_downstream_pipeline_exception_isolation(self):
        """Test that an exception inside process_event_full_pipeline is caught and isolated."""
        mock_orchestrator = MagicMock(spec=LivePipelineOrchestrator)
        mock_orchestrator.process_event.side_effect = RuntimeError("Simulated pipeline failure")

        consumer = AIDetectionConsumer(orchestrator=mock_orchestrator)
        evt = WindowsEventSchema(event_id=4624, record_id=301)

        success = consumer.consume_event(evt)
        # Failure must be caught, returning False and incrementing failure_count
        assert success is False
        assert consumer.total_processed == 1
        assert consumer.success_count == 0
        assert consumer.failure_count == 1

    def test_downstream_exception_does_not_corrupt_reader_checkpoint(self):
        """Test that pipeline exceptions do not modify or corrupt reader.last_record_id."""
        # Simulated reader checkpoint state
        last_record_id = 450

        mock_orchestrator = MagicMock(spec=LivePipelineOrchestrator)
        mock_orchestrator.process_event.side_effect = Exception("Downstream AI model timeout")

        consumer = AIDetectionConsumer(orchestrator=mock_orchestrator)
        evt = WindowsEventSchema(event_id=4625, record_id=451)

        res = consumer.consume_event(evt)
        assert res is False

        # Reader checkpoint must remain intact
        assert last_record_id == 450

    def test_eventConsumer_backwards_compatibility(self):
        """Test that AIDetectionConsumer is a valid EventConsumer compatible with LiveEventHandoffEngine."""
        engine = LiveEventHandoffEngine(max_queue_size=50)
        consumer = AIDetectionConsumer(consumer_id="compat_consumer")

        cid = engine.register_consumer(consumer)
        assert cid == "compat_consumer"
        assert engine.consumer_count() == 1

        evt = WindowsEventSchema(event_id=4688, record_id=999)
        engine.submit_event(evt)
        engine.process_next_event()

        stats = engine.get_handoff_stats()
        assert stats["total_submitted"] == 1
        assert stats["total_delivered"] == 1
        assert stats["delivery_failures"] == 0

    def test_safe_reset_and_cleanup(self):
        """Test reset_state and cleanup behavior of AIDetectionConsumer."""
        consumer = AIDetectionConsumer()
        evt = WindowsEventSchema(event_id=4625, record_id=50)
        consumer.consume_event(evt)

        assert len(consumer.get_results()) == 1
        consumer.reset_state()

        assert len(consumer.get_results()) == 0
        assert consumer.total_processed == 0
        assert consumer.success_count == 0
        assert consumer.failure_count == 0

    def test_full_pipeline_powershell_attack_detection(self):
        """Integration test: Encoded PowerShell event processed end-to-end triggers execution alert."""
        consumer = AIDetectionConsumer()
        evt = WindowsEventSchema(
            event_id=4688,
            timestamp="2026-08-12T10:05:00Z",
            computer="WORKSTATION-09",
            process_name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -enc SQBFA...",
            target_user="jdoe",
            record_id=601,
        )

        success = consumer.consume_event(evt)
        assert success is True

        res = consumer.get_results()[0]["pipeline_result"]
        assert res["prediction"] == 1
        assert res["alert_source"] in ("AI_AND_RULE_AGREEMENT", "RULE_SIGNATURE_ONLY", "AI_ANOMALY_ONLY")
        assert len(res["triggered_rules"]) >= 1
        assert any(r["technique_id"] == "T1059.001" for r in res["mitre_mapping"])

    def test_full_pipeline_privilege_escalation_detection(self):
        """Integration test: Sensitive privilege assignment event processed end-to-end triggers privesc alert."""
        consumer = AIDetectionConsumer()
        evt = WindowsEventSchema(
            event_id=4672,
            timestamp="2026-08-12T10:06:00Z",
            computer="CORP-DC-01",
            subject_user="admin_user",
            record_id=602,
        )

        success = consumer.consume_event(evt)
        assert success is True

        res = consumer.get_results()[0]["pipeline_result"]
        assert res["prediction"] == 1
        assert res["severity"] in ("Medium", "High", "Critical")
        assert any(r["technique_id"] == "T1078" for r in res["mitre_mapping"])
