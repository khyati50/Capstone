"""ai.collection — Windows Event Collector Foundation Package.

Module-level exports for Phase 1, Phase 2.1, Phase 2.2, and Phase 2.3 using lazy imports
to prevent sys.modules conflicts when running CLI submodules.

Exports:
  - WindowsEventSchema        : Canonical internal event representation
  - WindowsEventCollector     : Primary batch ingestion engine (JSON & EVTX files)
  - LiveWindowsEventReader    : Local Windows Security Event Log acquisition engine
  - LocalSecurityLogMonitor   : Continuous background Security Event Log monitor
  - LiveEventHandoffEngine    : Boundary engine for delivering live events to consumers
  - EventConsumer             : Abstract base class for downstream event consumers
  - FunctionEventConsumer     : Function wrapper for event consumers
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

__all__ = [
    "WindowsEventSchema",
    "WindowsEventCollector",
    "LiveWindowsEventReader",
    "LocalSecurityLogMonitor",
    "LiveEventHandoffEngine",
    "EventConsumer",
    "FunctionEventConsumer",
    "normalize_json_event",
    "normalize_evtx_record",
    "normalize_live_xml_event",
    "REQUIRED_FIELDS",
    "MONITORED_EVENT_IDS",
    "LOG_CHANNELS",
]


def __getattr__(name: str):
    """Lazy module-level export resolver preventing pre-import RuntimeWarnings."""
    if name == "WindowsEventCollector":
        from ai.collection.evtx_collector import WindowsEventCollector

        return WindowsEventCollector
    elif name in ("normalize_json_event", "normalize_evtx_record"):
        from ai.collection.normalizer import normalize_json_event, normalize_evtx_record

        return normalize_json_event if name == "normalize_json_event" else normalize_evtx_record
    elif name == "normalize_live_xml_event":
        from ai.collection.live_normalizer import normalize_live_xml_event

        return normalize_live_xml_event
    elif name == "LiveWindowsEventReader":
        from ai.collection.live_reader import LiveWindowsEventReader

        return LiveWindowsEventReader
    elif name == "LocalSecurityLogMonitor":
        from ai.collection.live_monitor import LocalSecurityLogMonitor

        return LocalSecurityLogMonitor
    elif name in ("LiveEventHandoffEngine", "EventConsumer", "FunctionEventConsumer", "MinimalTestConsumer"):
        from ai.collection.live_handoff import (
            LiveEventHandoffEngine,
            EventConsumer,
            FunctionEventConsumer,
            MinimalTestConsumer,
        )

        if name == "LiveEventHandoffEngine":
            return LiveEventHandoffEngine
        elif name == "EventConsumer":
            return EventConsumer
        elif name == "FunctionEventConsumer":
            return FunctionEventConsumer
        else:
            return MinimalTestConsumer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
