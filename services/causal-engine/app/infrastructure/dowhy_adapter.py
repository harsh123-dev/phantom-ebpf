"""
causal-engine DoWhy causal estimator adapter (re-export for backward compatibility).

Re-exports DoWhyCausalEstimator and _confidence_band from dowhy_estimator.py.
"""

from __future__ import annotations

from app.infrastructure.dowhy_estimator import DoWhyCausalEstimator, _confidence_band

__all__ = [
    "DoWhyCausalEstimator",
    "_confidence_band",
]
