"""ai.collection — Windows Event Collector Foundation Package.

Phase 1, 2.1 & 2.2 Exports:
  - WindowsEventSchema        : Canonical internal event representation
  - WindowsEventCollector     : Primary batch ingestion engine (JSON & EVTX files)
  - LiveWindowsEventReader    : Local Windows Security Event Log acquisition engine
  - LocalSecurityLogMonitor   : Continuous background Security Event Log monitor
  - normalize_json_event      : JSON event normalizer
  - normalize_evtx_record     : EVTX binary record normalizer
  - normalize_live_xml_event   : Live Windows Event Log XML normalizer
  - REQUIRED_FIELDS           : Minimum field list for validation
  - MONITORED_EVENT_IDS       : Windows Event IDs monitored by detection pipeline
"""

from ai.collection.schema import (
    WindowsEventSchema,
    REQUIRED_FIELDS,
    MONITORED_EVENT_IDS,
    LOG_CHANNELS,
)
from ai.collection.normalizer import normalize_json_event, normalize_evtx_record
from ai.collection.evtx_collector import WindowsEventCollector
from ai.collection.live_normalizer import normalize_live_xml_event
from ai.collection.live_reader import LiveWindowsEventReader
from ai.collection.live_monitor import LocalSecurityLogMonitor

__all__ = [
    "WindowsEventSchema",
    "WindowsEventCollector",
    "LiveWindowsEventReader",
    "LocalSecurityLogMonitor",
    "normalize_json_event",
    "normalize_evtx_record",
    "normalize_live_xml_event",
    "REQUIRED_FIELDS",
    "MONITORED_EVENT_IDS",
    "LOG_CHANNELS",
]
