"""ai.collection CLI entry point — invoked via python -m ai.collection.evtx_collector.

Provides:
  --help     Show usage and exit
  --path     Root directory to scan (default: DATASET_ROOT from ai/config.py)
  --type     File type: json (default) or evtx
  --demo     Force demo mode with 3 synthetic events
  --version  Print version and exit

Phase 1 - Windows Event Collector Foundation
"""

import argparse
import json
import tempfile
from pathlib import Path

from ai.collection.evtx_collector import WindowsEventCollector
from ai.config import DATASET_ROOT


# ------------------------------------------------------------------------------
# ASCII-safe output helpers (Windows cp1252 compatible)
# ------------------------------------------------------------------------------


def _sep(ch: str = "-") -> None:
    """Print a 72-char separator line using the given character."""
    print(ch * 72)


def _p(msg: str = "") -> None:
    """Print a single output line."""
    print(msg)


# ------------------------------------------------------------------------------
# Smoke-test functions
# ------------------------------------------------------------------------------


def run_smoke_test(dataset_root: Path, file_type: str = "json") -> None:
    """Collect from dataset_root and print a health report.

    Args:
        dataset_root: Root directory to scan recursively.
        file_type: 'json' (default) or 'evtx'.
    """
    collector = WindowsEventCollector()
    _sep("=")
    _p("  Windows Event Collector - Phase 1 Smoke-Test")
    _sep("=")
    _p(f"  Dataset root : {dataset_root}")
    _p(f"  File type    : {file_type.upper()}")
    _p()

    if not dataset_root.exists():
        _p(f"[WARN]  Dataset not found: {dataset_root}")
        _p("        Tip: pass a real path with --path, or use --demo.")
        _p()
        run_demo(collector)
        return

    _p(f"[INFO]  Scanning {file_type.upper()} files recursively...")
    events = collector.collect_from_directory(dataset_root, file_type=file_type)
    print_report(collector.get_collection_stats(), events[:5] if events else [])


def run_demo(collector: WindowsEventCollector) -> None:
    """Run synthetic in-memory demo when no real dataset is available.

    Args:
        collector: A fresh WindowsEventCollector instance to use.
    """
    samples = [
        {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                    "EventID": 4625,
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-08-07T04:00:00Z"}},
                    "Computer": "CORP-DC-01",
                    "Channel": "Security",
                },
                "EventData": {
                    "TargetUserName": "administrator",
                    "IpAddress": "192.168.1.50",
                    "LogonType": "3",
                },
            }
        },
        {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                    "EventID": 4688,
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-08-07T04:01:00Z"}},
                    "Computer": "WORKSTATION-03",
                    "Channel": "Security",
                },
                "EventData": {
                    "TargetUserName": "jdoe",
                    "NewProcessName": "C:/Windows/System32/powershell.exe",
                    "CommandLine": "powershell.exe -ExecutionPolicy Bypass -EncodedCommand SQBF...",
                    "LogonType": "0",
                },
            }
        },
        {
            "Event": {
                "System": {
                    "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                    "EventID": 4672,
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-08-07T04:02:00Z"}},
                    "Computer": "CORP-DC-01",
                    "Channel": "Security",
                },
                "EventData": {
                    "SubjectUserName": "svc_account",
                    "LogonType": "2",
                },
            }
        },
    ]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8", prefix="demo_"
    ) as fh:
        json.dump(samples, fh)
        tmp = Path(fh.name)

    events = collector.collect_from_json_file(tmp)
    tmp.unlink(missing_ok=True)
    print_report(collector.get_collection_stats(), events)


def print_report(stats: dict, sample_events: list) -> None:  # type: ignore[type-arg]
    """Print ASCII-safe collection health report to stdout.

    Args:
        stats: Output of WindowsEventCollector.get_collection_stats().
        sample_events: Up to 5 WindowsEventSchema instances to display.
    """
    health = stats["collection_health"]
    icon = {"healthy": "[OK]  ", "degraded": "[WARN]", "failed": "[FAIL]"}.get(health, "[????]")

    _sep("-")
    _p("  COLLECTION HEALTH REPORT")
    _sep("-")
    _p(f"  {icon}  Collection health     : {health.upper()}")
    _p(f"         Files processed      : {stats['total_files_processed']}")
    _p(f"         Events collected     : {stats['total_events_collected']}")
    _p(f"         Validation failures  : {stats['total_validation_failures']}")

    dist = stats["event_id_distribution"]
    if dist:
        _p()
        _p("  Event ID Distribution (top 10):")
        for eid, cnt in sorted(dist.items(), key=lambda x: -x[1])[:10]:
            bar = "#" * min(cnt, 40)
            _p(f"    EventID {eid:>6}  {bar}  ({cnt})")

    if stats["failed_files"]:
        _p()
        _p(f"  Failed files ({len(stats['failed_files'])}):")
        for ff in stats["failed_files"][:5]:
            _p(f"    - {ff}")

    if sample_events:
        _p()
        _p(f"  Sample Normalized Events (first {len(sample_events)}):")
        for i, evt in enumerate(sample_events, 1):
            tag = "MONITORED" if evt.is_monitored_event() else "general  "
            _p(
                f"    [{i}] EventID={evt.event_id:<6} "
                f"Computer={evt.computer:<20} "
                f"User={evt.target_user:<15} [{tag}]"
            )

    _p()
    _sep("-")
    _p("  Phase 1 - WindowsEventCollector ready.")
    _sep("=")


# ------------------------------------------------------------------------------
# argparse entry point
# ------------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m ai.collection.evtx_collector",
        description=(
            "Phase 1 Windows Event Collector - Smoke-Test & Health Report\n"
            "\n"
            "Recursively collects Windows Security Event Logs from JSON or EVTX\n"
            "files, normalizes each record to WindowsEventSchema, validates\n"
            "required fields (EventID, TimeCreated, Computer), and prints a\n"
            "structured collection health report.\n"
            "\n"
            "If the dataset directory is not found, demo mode runs automatically\n"
            "with 3 synthetic event records to verify the pipeline is working."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m ai.collection.evtx_collector\n"
            "  python -m ai.collection.evtx_collector --demo\n"
            "  python -m ai.collection.evtx_collector --path C:/logs --type json\n"
            "  python -m ai.collection.evtx_collector --path C:/evtx --type evtx\n"
        ),
    )
    parser.add_argument(
        "--path",
        "-p",
        metavar="DIR",
        default=str(DATASET_ROOT),
        help="Root directory to scan recursively (default: DATASET_ROOT from ai/config.py)",
    )
    parser.add_argument(
        "--type",
        "-t",
        metavar="TYPE",
        choices=["json", "evtx"],
        default="json",
        help="File type to collect: json (default) or evtx",
    )
    parser.add_argument(
        "--demo",
        "-d",
        action="store_true",
        help="Force demo mode with 3 synthetic events (bypasses real dataset scan)",
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version="WindowsEventCollector Phase-1 v1.0.0",
    )
    return parser


if __name__ == "__main__":
    args = build_parser().parse_args()

    if args.demo:
        _sep("=")
        _p("  Windows Event Collector - Phase 1 (Demo Mode)")
        _sep("=")
        _p()
        run_demo(WindowsEventCollector())
    else:
        run_smoke_test(Path(args.path), file_type=args.type)
