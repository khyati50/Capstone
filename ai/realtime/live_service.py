"""Continuous Real-Time Windows Live Security Ingestion Service.

Wires together the complete 4-tier live runtime pipeline:
  1. LocalSecurityLogMonitor (ai.collection.live_monitor) -> Reads live Windows Security EVTX log
  2. LiveEventHandoffEngine (ai.collection.live_handoff) -> Bounded thread-safe queue with backpressure
  3. AIDetectionConsumer (ai.realtime.detection_consumer) -> Feature bridge & LivePipelineOrchestrator
  4. LiveResultDispatcher (ai.realtime.result_dispatcher) -> Dispatches to Express backend via HTTP POST

Phase 13E — Real Windows Live Pipeline Runtime
"""

import argparse
import logging
import signal
import sys
import time
from typing import Any, Dict

from ai.collection.live_handoff import LiveEventHandoffEngine
from ai.collection.live_monitor import LocalSecurityLogMonitor
from ai.collection.live_reader import LiveWindowsEventReader
from ai.realtime.detection_consumer import AIDetectionConsumer
from ai.realtime.result_dispatcher import LiveResultDispatcher

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("LiveSecurityService")


class LiveSecurityPipelineService:
    """Coordinates and executes the full Windows Security log live ingestion daemon."""

    def __init__(
        self,
        poll_interval_sec: float = 1.0,
        backend_url: str = "http://localhost:5000/api/events/pipeline-result",
        channel: str = "Security",
        max_queue_size: int = 1000,
    ) -> None:
        """Initialize all 4 pipeline tiers.

        Args:
            poll_interval_sec: Seconds between Security Log polling ticks.
            backend_url: Target Express backend pipeline-result endpoint.
            channel: Windows Event Log channel (default 'Security').
            max_queue_size: Capacity of the handoff buffer.
        """
        self.poll_interval_sec = poll_interval_sec
        self.backend_url = backend_url
        self.channel = channel
        self.max_queue_size = max_queue_size
        self.is_running = False

        # Tier 4: Backend HTTP Result Dispatcher
        self.dispatcher = LiveResultDispatcher(
            backend_url=self.backend_url,
            timeout=3.0,
        )

        # Tier 3: AI Threat Detection Consumer
        self.consumer = AIDetectionConsumer(
            consumer_id="live_windows_detection_consumer",
            result_callback=self._handle_pipeline_result,
        )

        # Tier 2: Thread-Safe Handoff Engine
        self.handoff_engine = LiveEventHandoffEngine(
            max_queue_size=self.max_queue_size,
            overflow_policy="drop_oldest",
        )
        self.handoff_engine.register_consumer(self.consumer)

        # Tier 1: Local Windows Security Event Log Continuous Monitor
        self.reader = LiveWindowsEventReader(channel=self.channel)
        self.monitor = LocalSecurityLogMonitor(
            poll_interval_sec=self.poll_interval_sec,
            reader=self.reader,
        )
        # Register monitor callback to forward raw events into handoff queue
        self.monitor.add_listener(lambda evt: self.handoff_engine.submit_event(evt))

    def _handle_pipeline_result(self, pipeline_result: Dict[str, Any]) -> bool:
        """Forward AI pipeline result to Express backend and log activity."""
        success = self.dispatcher.dispatch_result(pipeline_result)
        raw = pipeline_result.get("raw_event", {})
        eid = raw.get("EventID") or raw.get("event_id")
        comp = raw.get("Computer") or raw.get("computer")
        user = raw.get("TargetUserName") or raw.get("username")
        sev = pipeline_result.get("severity", "Benign")
        pred = pipeline_result.get("prediction", 0)

        status_str = "[ALERT]" if pred == 1 or sev in ("Critical", "High") else "[BENIGN]"
        logger.info(f"{status_str} EventID={eid} Host={comp} User={user} Sev={sev} -> Dispatched to Backend: {success}")
        return success

    def start(self) -> None:
        """Start all pipeline background threads."""
        if self.is_running:
            return
        self.is_running = True
        logger.info("=" * 70)
        logger.info("  AEGIS-XAI Continuous Windows Security Live Ingestion Service")
        logger.info("=" * 70)
        logger.info(f"  Channel       : {self.channel}")
        logger.info(f"  Poll Interval : {self.poll_interval_sec}s")
        logger.info(f"  Backend URL   : {self.backend_url}")
        logger.info("  Starting Handoff Engine & Monitor Daemon...")

        self.handoff_engine.start_handoff()
        self.monitor.start_monitoring()
        logger.info("[READY] Live ingestion active. Polling real Windows Security events...")

    def stop(self) -> None:
        """Gracefully terminate background monitor and handoff threads."""
        if not self.is_running:
            return
        logger.info("Stopping Live Security Pipeline Service...")
        self.monitor.stop_monitoring()
        self.handoff_engine.stop_handoff()
        self.is_running = False
        logger.info("Live Security Pipeline Service stopped cleanly.")

    def get_summary(self) -> Dict[str, Any]:
        """Return cumulative runtime performance statistics."""
        mon_stat = self.monitor.get_monitor_status()
        hnd_stat = self.handoff_engine.get_handoff_stats()
        return {
            "state": "RUNNING" if self.is_running else "STOPPED",
            "total_polls": mon_stat["total_polls"],
            "events_captured": mon_stat["total_events_emitted"],
            "events_handed_off": hnd_stat["total_submitted"],
            "events_ai_processed": self.consumer.total_processed,
            "events_dispatched": self.dispatcher.total_dispatched,
            "successful_dispatches": self.dispatcher.successful_dispatches,
            "failed_dispatches": self.dispatcher.failed_dispatches,
            "last_record_id": mon_stat["reader"]["last_record_id"],
        }


def main() -> None:
    """CLI entry point for python -m ai.realtime.live_service."""
    parser = argparse.ArgumentParser(description="AEGIS-XAI Windows Security Log Real-Time Ingestion Service")
    parser.add_argument("--interval", "-i", type=float, default=1.0, help="Polling interval in seconds (default: 1.0)")
    parser.add_argument("--duration", "-d", type=float, default=0.0, help="Run duration in seconds (0 = run forever)")
    parser.add_argument(
        "--backend-url",
        "-u",
        type=str,
        default="http://localhost:5000/api/events/pipeline-result",
        help="Express backend ingest URL (default: http://localhost:5000/api/events/pipeline-result)",
    )
    parser.add_argument(
        "--channel", "-c", type=str, default="Security", help="Windows Event Log channel (default: Security)"
    )
    args = parser.parse_args()

    service = LiveSecurityPipelineService(
        poll_interval_sec=args.interval,
        backend_url=args.backend_url,
        channel=args.channel,
    )

    def _sig_handler(sig, frame):
        logger.info(f"Received signal {sig}. Initiating graceful shutdown...")
        service.stop()
        summary = service.get_summary()
        print("\n" + "=" * 70)
        print("  LIVE INGESTION SUMMARY REPORT")
        print("=" * 70)
        for k, v in summary.items():
            print(f"  {k:<24}: {v}")
        print("=" * 70)
        sys.exit(0)

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    service.start()

    try:
        if args.duration > 0:
            time.sleep(args.duration)
            service.stop()
            summary = service.get_summary()
            print("\n" + "=" * 70)
            print("  LIVE INGESTION SUMMARY REPORT")
            print("=" * 70)
            for k, v in summary.items():
                print(f"  {k:<24}: {v}")
            print("=" * 70)
        else:
            while True:
                time.sleep(1.0)
    except KeyboardInterrupt:
        _sig_handler(signal.SIGINT, None)


if __name__ == "__main__":
    main()
