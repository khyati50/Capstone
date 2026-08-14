"""ai.realtime — Windows Real-Time Ingestion & Feature Bridge Package.

Exports:
  - RealTimeEventBuffer          : Thread-safe bounded event queue
  - StreamMetricsCalculator      : Live EPS and processing latency calculator
  - RealTimeStreamListener       : Background event dispatcher with subscriber callbacks
  - RealTimeFeatureBridge        : Live event to model feature vector extractor
  - RealTimeFeatureVector        : Extracted model feature vector dataclass
  - FileTailProducer             : Tail JSON/EVTX files in real-time
  - WinEvtLogProducer            : Live Windows Security Event Log API producer
  - SyntheticStreamProducer      : Real-time scenario event stream generator
  - AIDetectionConsumer          : Bridge live events to AI threat detection pipeline
  - LiveResultDispatcher         : Dispatches results to Express backend
  - LiveSecurityPipelineService  : Full continuous live Security log ingestion daemon
"""

from ai.realtime.buffer import RealTimeEventBuffer
from ai.realtime.detection_consumer import AIDetectionConsumer
from ai.realtime.feature_bridge import RealTimeFeatureBridge, RealTimeFeatureVector
from ai.realtime.listener import RealTimeStreamListener
from ai.realtime.live_service import LiveSecurityPipelineService
from ai.realtime.metrics import StreamMetricsCalculator
from ai.realtime.producers import (
    BaseStreamProducer,
    FileTailProducer,
    SyntheticStreamProducer,
    WinEvtLogProducer,
)
from ai.realtime.result_dispatcher import LiveResultDispatcher

__all__ = [
    "RealTimeEventBuffer",
    "StreamMetricsCalculator",
    "RealTimeStreamListener",
    "RealTimeFeatureBridge",
    "RealTimeFeatureVector",
    "AIDetectionConsumer",
    "LiveResultDispatcher",
    "LiveSecurityPipelineService",
    "BaseStreamProducer",
    "FileTailProducer",
    "WinEvtLogProducer",
    "SyntheticStreamProducer",
]
