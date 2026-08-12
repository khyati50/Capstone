"""AI Detection Consumer — Phase 2.3 -> Phase 3 Real-Time Pipeline Adapter.

Receives normalized WindowsEventSchema records from LiveEventHandoffEngine,
extracts behavioral features via RealTimeFeatureBridge, and passes the merged
feature dictionary to LivePipelineOrchestrator for downstream AI processing.

Phase 3 — Real-Time AI Threat Detection Integration
"""

import logging
import threading
from typing import Any, Callable, Dict, List, Optional

from ai.collection.live_handoff import EventConsumer
from ai.collection.schema import WindowsEventSchema
from ai.pipeline.orchestrator import LivePipelineOrchestrator
from ai.realtime.feature_bridge import RealTimeFeatureBridge

logger = logging.getLogger("AIDetectionConsumer")


class AIDetectionConsumer(EventConsumer):
    """Consumer bridging live Windows events to the AI threat detection pipeline."""

    def __init__(
        self,
        consumer_id: str = "ai_detection_consumer",
        orchestrator: Optional[LivePipelineOrchestrator] = None,
        feature_bridge: Optional[RealTimeFeatureBridge] = None,
        result_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> None:
        """Initialize AIDetectionConsumer.

        Args:
            consumer_id: Unique string identifier for consumer.
            orchestrator: LivePipelineOrchestrator instance (created if None).
            feature_bridge: RealTimeFeatureBridge instance (created if None).
            result_callback: Optional callback function triggered on pipeline_result output (e.g. LiveResultDispatcher).
        """
        super().__init__(consumer_id=consumer_id)
        self.orchestrator = orchestrator or LivePipelineOrchestrator()
        self.feature_bridge = feature_bridge or RealTimeFeatureBridge()
        self.result_callback = result_callback
        self.processed_results: List[Dict[str, Any]] = []
        self.total_processed: int = 0
        self.success_count: int = 0
        self.failure_count: int = 0
        self._lock = threading.Lock()

    def consume_event(self, event: WindowsEventSchema) -> bool:
        """Consume a normalized WindowsEventSchema record, compute features, and run AI pipeline.

        Args:
            event: Normalized WindowsEventSchema record.

        Returns:
            True if event was processed by AI pipeline successfully, False if error occurred.
        """
        try:
            # 1. Compute real-time rolling features using existing feature bridge
            feature_vec = self.feature_bridge.process_event(event)

            # 2. Merge event metadata dict and feature vector dict
            merged_dict = {**event.to_dict(), **feature_vec.to_dict()}

            # Ensure EventRecordID and record_id are explicitly preserved
            merged_dict["EventRecordID"] = event.record_id
            merged_dict["record_id"] = event.record_id

            # 3. Invoke downstream AI threat detection pipeline
            pipeline_result = self.orchestrator.process_event(merged_dict)

            with self._lock:
                self.total_processed += 1
                self.success_count += 1
                self.processed_results.append(
                    {
                        "record_id": event.record_id,
                        "event_id": event.event_id,
                        "pipeline_result": pipeline_result,
                    }
                )

            # 4. Phase 5 — Fan out live security result to DB/Socket.IO dispatcher if registered
            if self.result_callback is not None:
                try:
                    self.result_callback(pipeline_result)
                except Exception as cb_err:
                    logger.warning(f"[Phase 5 Dispatcher Warning] Callback error: {cb_err}")

            logger.info(
                f"[Phase 3 Consumer] RecordID={event.record_id} EventID={event.event_id} "
                f"-> Alert={pipeline_result.get('prediction') == 1} "
                f"Source={pipeline_result.get('alert_source')} "
                f"Risk={pipeline_result.get('risk_score')}"
            )
            return True

        except Exception as exc:
            with self._lock:
                self.total_processed += 1
                self.failure_count += 1

            logger.error(
                f"[Phase 3 Consumer] Error processing RecordID={getattr(event, 'record_id', 'unknown')}: {exc}",
                exc_info=True,
            )
            return False

    def get_results(self) -> List[Dict[str, Any]]:
        """Return thread-safe copy of processed results list."""
        with self._lock:
            return list(self.processed_results)

    def reset_state(self) -> None:
        """Reset consumer results and internal orchestrator/feature_bridge states."""
        with self._lock:
            self.processed_results.clear()
            self.total_processed = 0
            self.success_count = 0
            self.failure_count = 0
        self.feature_bridge.reset_state()
        self.orchestrator.reset_state()
