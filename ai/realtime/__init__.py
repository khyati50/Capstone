"""ai.realtime — Windows Real-Time Ingestion & Feature Bridge Package.

Exports:
  - RealTimeEventBuffer     : Thread-safe bounded event queue
  - StreamMetricsCalculator : Live EPS and processing latency calculator
  - RealTimeStreamListener  : Background event dispatcher with subscriber callbacks
  - RealTimeFeatureBridge   : Live event to model feature vector extractor
  - RealTimeFeatureVector   : Extracted model feature vector dataclass
  - FileTailProducer        : Tail JSON/EVTX files in real-time
  - WinEvtLogProducer       : Live Windows Security Event Log API producer
  - SyntheticStreamProducer : Real-time scenario event stream generator
"""

from ai.realtime.buffer import RealTimeEventBuffer
from ai.realtime.metrics import StreamMetricsCalculator
from ai.realtime.listener import RealTimeStreamListener
from ai.realtime.feature_bridge import RealTimeFeatureBridge, RealTimeFeatureVector
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
    "RealTimeFeatureBridge",
    "RealTimeFeatureVector",
    "BaseStreamProducer",
    "FileTailProducer",
    "WinEvtLogProducer",
    "SyntheticStreamProducer",
]
