"""Explainability & Security Intelligence Layer Package Initialization.

SecurityIntelligenceLayer is imported eagerly (no optional dependencies).
ShapExplainer is imported lazily so that environments where the optional
'shap' package is not installed can still import SecurityIntelligenceLayer
without error.
"""

from .security_intel import SecurityIntelligenceLayer

__all__ = [
    "ShapExplainer",
    "SecurityIntelligenceLayer",
]


def __getattr__(name: str):
    """Lazy loader for optional shap-dependent explainability components."""
    if name == "ShapExplainer":
        from .shap_explainer import ShapExplainer

        return ShapExplainer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
