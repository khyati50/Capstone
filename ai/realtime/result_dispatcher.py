"""Live Result Dispatcher — Phase 5 HTTP Bridge to Express Backend & Database.

Dispatches complete pipeline_result dictionaries produced by AIDetectionConsumer to
the Node.js Express backend API (POST /api/events/pipeline-result) for MySQL
persistence and Socket.IO real-time broadcasting.

Phase 5 — Database & Socket.IO Integration
"""

import json
import logging
import urllib.error
import urllib.request

logger = logging.getLogger("LiveResultDispatcher")


class LiveResultDispatcher:
    """Dispatches live threat detection pipeline results to Express backend for DB/Socket.IO."""

    def __init__(
        self,
        backend_url: str = "http://localhost:5000/api/events/pipeline-result",
        timeout: float = 3.0,
        auth_token: str = None,
    ) -> None:
        """Initialize LiveResultDispatcher.

        Args:
            backend_url: Full HTTP URL for backend pipeline-result endpoint.
            timeout: HTTP request timeout in seconds.
            auth_token: Optional Bearer JWT token for authenticated endpoints.
        """
        self.backend_url = backend_url
        self.timeout = timeout
        self.auth_token = auth_token
        self.total_dispatched: int = 0
        self.successful_dispatches: int = 0
        self.failed_dispatches: int = 0

    def dispatch_result(self, pipeline_result: dict) -> bool:
        """Dispatch a single pipeline_result dictionary to the Express backend.

        Args:
            pipeline_result: Complete security result dictionary from LivePipelineOrchestrator.

        Returns:
            True if HTTP post succeeded (HTTP 200/201), False if connection failed or error returned.
        """
        self.total_dispatched += 1
        try:
            payload_bytes = json.dumps(pipeline_result).encode("utf-8")
            req = urllib.request.Request(
                self.backend_url,
                data=payload_bytes,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "Antigravity-AI-LiveDispatcher/1.0",
                    **({"Authorization": f"Bearer {self.auth_token}"} if self.auth_token else {}),
                },
                method="POST",
            )

            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if 200 <= resp.status < 300:
                    self.successful_dispatches += 1
                    logger.debug(f"[Phase 5 Dispatcher] Result dispatched successfully to {self.backend_url}")
                    return True
                else:
                    self.failed_dispatches += 1
                    logger.warning(f"[Phase 5 Dispatcher] Unexpected HTTP status {resp.status} from backend")
                    return False

        except urllib.error.URLError as err:
            self.failed_dispatches += 1
            logger.warning(f"[Phase 5 Dispatcher] Backend unreachable ({err.reason}). Ingestion continues.")
            return False
        except Exception as exc:
            self.failed_dispatches += 1
            logger.error(f"[Phase 5 Dispatcher] Error dispatching result: {exc}")
            return False

    def reset_stats(self) -> None:
        """Reset dispatcher performance counters."""
        self.total_dispatched = 0
        self.successful_dispatches = 0
        self.failed_dispatches = 0
