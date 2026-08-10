"""Negative Test Suite for Threat Detection Engine.

Validates robust error handling for edge cases:
- Corrupted JSON log files
- Missing required fields in events
- Unknown or invalid Event IDs
- Missing model artifact files
- Invalid SHAP inputs
- Empty input datasets
"""

import json
import pytest
from pathlib import Path
from typing import Dict, Any

from ai.preprocessing.parser import parse_scenario_json, parse_all_scenarios, get_last_parser_summary
from ai.preprocessing.feature_engineering import engineer_features
from ai.detection.hybrid_engine import HybridDetectionEngine
from ai.prediction.service import PredictionService
from ai.explainability.security_intel import SecurityIntelligenceLayer
from ai.explainability.shap_explainer import ShapExplainer
from ai.mitre.mapper import MitreMapper
from ai.correlation.event_correlator import EventCorrelator


class TestNegativeCases:
    """Test suite verifying robust handling of invalid inputs and failure modes."""

    def test_corrupted_json_parsing(self, tmp_path):
        """Corrupted or truncated JSON file should log error and return empty list without crashing."""
        corrupted_file = tmp_path / "corrupted_log.json"
        corrupted_file.write_text("{'invalid_json': True, truncation...}", encoding="utf-8")

        records = parse_scenario_json(corrupted_file)
        assert isinstance(records, list)
        assert len(records) == 0

        summary = get_last_parser_summary()
        assert isinstance(summary, dict)

    def test_nonexistent_json_file(self):
        """Parsing non-existent file path should handle gracefully."""
        records = parse_scenario_json(Path("non_existent_file_123.json"))
        assert records == []

    def test_missing_fields_in_feature_engineering(self):
        """Empty or sparse DataFrame should process without throwing KeyErrors."""
        import pandas as pd

        sparse_df = pd.DataFrame([{"Computer": "HOST-01"}])
        res = engineer_features(sparse_df)

        assert "failed_login_count_5m" in res.columns
        assert "is_powershell_executed" in res.columns
        assert "label" in res.columns

    def test_unknown_event_id(self):
        """Unknown Event ID should fall back to baseline handling."""
        mapper = MitreMapper()
        evt = {"EventID": 99999, "raw_event": {"EventID": 99999}}
        mapped = mapper.map_event_to_mitre(evt)

        assert isinstance(mapped, list)
        assert len(mapped) > 0
        assert any(m["technique_id"] == "T1036" or m["tactic"] == "Defense Evasion" for m in mapped)

    def test_missing_model_file_fallback(self, tmp_path):
        """PredictionService instantiated with invalid artifact dir should handle gracefully."""
        svc = PredictionService(artifacts_dir=tmp_path / "empty_dir")
        res = svc.predict_single({"scenario_id": "test"})

        assert "prediction" in res
        assert "confidence" in res
        assert res["model_version"].startswith("heuristic") or res["model_version"].startswith("v1.0.0")

    def test_invalid_shap_input(self):
        """SHAP explainer with missing feature weights should return safe fallback explanations."""
        intel = SecurityIntelligenceLayer()
        alert = {"severity": "High", "confidence": 0.9, "raw_event": {"Computer": "HOST-01"}}
        res = intel.generate_intelligence_package(alert, {})

        assert "human_readable_explanation" in res
        assert len(res["human_readable_explanation"]) > 0

    def test_event_correlator_empty_event(self):
        """Correlator handling empty or sparse alert dictionary."""
        correlator = EventCorrelator()
        res = correlator.correlate_event({})

        assert "incident_id" in res
        assert res["chain_length"] >= 1
