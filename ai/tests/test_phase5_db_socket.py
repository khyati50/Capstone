"""Phase 5 Test Suite — Database & Socket.IO Integration Verification.

Tests covering:
- LiveResultDispatcher payload formatting and HTTP request execution
- Connection error isolation in LiveResultDispatcher
- AIDetectionConsumer -> LiveResultDispatcher result_callback trigger
- Callback exception safety inside AIDetectionConsumer
- End-to-end Phase 5 pipeline result payload verification (17+ required fields)
"""

from unittest.mock import MagicMock, patch

from ai.collection.schema import WindowsEventSchema
from ai.realtime.detection_consumer import AIDetectionConsumer
from ai.realtime.result_dispatcher import LiveResultDispatcher


class TestPhase5DatabaseAndSocketIO:
    """Test suite for Phase 5 live pipeline database persistence & Socket.IO broadcasting integration."""

    def test_live_result_dispatcher_success(self):
        """Test LiveResultDispatcher successfully posts pipeline_result to backend HTTP URL."""
        dispatcher = LiveResultDispatcher(backend_url="http://localhost:5000/api/events/pipeline-result")
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.__enter__.return_value = mock_response

        sample_result = {
            "prediction": 1,
            "confidence": 0.95,
            "severity": "High",
            "risk_score": 75.0,
            "incident_id": "INC-TEST-01",
        }

        with patch("urllib.request.urlopen", return_value=mock_response) as mock_urlopen:
            success = dispatcher.dispatch_result(sample_result)
            assert success is True
            assert dispatcher.total_dispatched == 1
            assert dispatcher.successful_dispatches == 1
            assert dispatcher.failed_dispatches == 0
            mock_urlopen.assert_called_once()

    def test_live_result_dispatcher_connection_error_isolation(self):
        """Test LiveResultDispatcher catches network/HTTP errors without propagating exceptions."""
        dispatcher = LiveResultDispatcher(backend_url="http://localhost:5000/api/events/pipeline-result")

        sample_result = {"prediction": 0, "confidence": 0.2}

        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            success = dispatcher.dispatch_result(sample_result)
            assert success is False
            assert dispatcher.total_dispatched == 1
            assert dispatcher.successful_dispatches == 0
            assert dispatcher.failed_dispatches == 1

    def test_detection_consumer_triggers_result_callback(self):
        """Test AIDetectionConsumer invokes result_callback upon successful event processing."""
        mock_callback = MagicMock()
        consumer = AIDetectionConsumer(result_callback=mock_callback)

        evt = WindowsEventSchema(
            event_id=4625,
            timestamp="2026-08-12T10:00:00Z",
            computer="DC-01",
            target_user="admin",
            record_id=801,
        )

        success = consumer.consume_event(evt)
        assert success is True
        assert mock_callback.call_count == 1

        pipeline_res = mock_callback.call_args[0][0]
        assert "prediction" in pipeline_res
        assert "risk_score" in pipeline_res
        assert pipeline_res["raw_event"]["EventRecordID"] == 801

    def test_detection_consumer_callback_failure_isolation(self):
        """Test that an error inside result_callback does not break AIDetectionConsumer event processing."""
        faulty_callback = MagicMock(side_effect=RuntimeError("Backend API timeout"))
        consumer = AIDetectionConsumer(result_callback=faulty_callback)

        evt = WindowsEventSchema(event_id=4624, record_id=802)
        success = consumer.consume_event(evt)

        # Event consumption must still succeed, isolating callback failure
        assert success is True
        assert consumer.total_processed == 1
        assert consumer.success_count == 1
        assert faulty_callback.call_count == 1

    def test_full_phase5_pipeline_to_dispatcher_payload_contract(self):
        """Test that AIDetectionConsumer + LiveResultDispatcher delivers complete 17+ field security result payload."""
        mock_post = MagicMock()
        mock_post.status = 200
        mock_post.__enter__.return_value = mock_post

        dispatcher = LiveResultDispatcher()
        consumer = AIDetectionConsumer(result_callback=dispatcher.dispatch_result)

        evt = WindowsEventSchema(
            event_id=4688,
            timestamp="2026-08-12T10:05:00Z",
            computer="WORKSTATION-01",
            process_name="powershell.exe",
            command_line="powershell.exe -ExecutionPolicy Bypass -enc SQBFA...",
            target_user="jdoe",
            record_id=905,
        )

        with patch("urllib.request.urlopen", return_value=mock_post):
            success = consumer.consume_event(evt)
            assert success is True
            assert dispatcher.successful_dispatches == 1

        results = consumer.get_results()
        assert len(results) == 1
        res = results[0]["pipeline_result"]

        # Verify payload contract contains all 17+ required fields for DB/Socket.IO
        required_fields = [
            "prediction",
            "confidence",
            "severity",
            "alert_source",
            "model_version",
            "shap_values",
            "triggered_rules",
            "threat_summary",
            "threat_type",
            "explanation",
            "evidence_package",
            "recommendations",
            "incident_id",
            "chain_length",
            "is_multi_stage",
            "risk_score",
            "risk_level",
            "risk_breakdown",
            "risk_sublines",
            "mitre_mapping",
            "timeline_nodes",
            "raw_event",
        ]
        for field in required_fields:
            assert field in res, f"Missing required payload field '{field}' for DB/Socket.IO"
