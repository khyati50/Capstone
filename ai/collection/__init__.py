"""ai.collection — Windows Event Collector Foundation Package.

Phase 1 exports:
  - WindowsEventSchema   : Canonical internal event representation
  - WindowsEventCollector: Primary ingestion engine
  - normalize_json_event : JSON event normalizer
  - normalize_evtx_record: EVTX binary record normalizer
  - REQUIRED_FIELDS      : Minimum field list for validation
  - MONITORED_EVENT_IDS  : Windows Event IDs monitored by detection pipeline
"""

from ai.collection.schema import (
    WindowsEventSchema,
    REQUIRED_FIELDS,
    MONITORED_EVENT_IDS,
    LOG_CHANNELS,
)
from ai.collection.normalizer import normalize_json_event, normalize_evtx_record
from ai.collection.evtx_collector import WindowsEventCollector

__all__ = [
    "WindowsEventSchema",
    "WindowsEventCollector",
    "normalize_json_event",
    "normalize_evtx_record",
    "REQUIRED_FIELDS",
    "MONITORED_EVENT_IDS",
    "LOG_CHANNELS",
]
