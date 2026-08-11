"""ai.realtime — Windows Real-Time Ingestion & Streaming Package.

Phase 2.1 exports:
  - RealTimeEventBuffer: Thread-safe bounded event queue
  - StreamMetricsCalculator: Live EPS and processing latency calculator
  - RealTimeStreamListener: Background event dispatcher with subscriber callbacks
  - FileTailProducer: Tail JSON/EVTX files in real-time
  - WinEvtLogProducer: Live Windows Security Event Log API producer
  - SyntheticStreamProducer: Real-time scenario event stream generator
"""

from ai.realtime.buffer import RealTimeEventBuffer
from ai.realtime.metrics import StreamMetricsCalculator
from ai.realtime.listener import RealTimeStreamListener
from ai.realtime.producers import (
    BaseStreamProducer,
    FileTailProducer,
    WinEvtLogProducer,
    SyntheticStreamProducer,
)

__all__ = [
    "RealTimeEventBuffer",
    "StreamMetricsCalculator",
    "RealTimeStreamListener",
    "BaseStreamProducer",
    "FileTailProducer",
    "WinEvtLogProducer",
    "SyntheticStreamProducer",
]
