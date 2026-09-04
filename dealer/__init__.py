"""The Dealer — grading core for blue-team investigation reps.

Public API:
    from dealer import grade, GroundTruth, Verdict
"""
from .schema import GroundTruth, Verdict, SchemaError, load_ground_truth, load_verdict
from .grader import grade, Report, LineItem

__version__ = "0.1.0"
__all__ = [
    "grade", "Report", "LineItem",
    "GroundTruth", "Verdict", "SchemaError",
    "load_ground_truth", "load_verdict",
]
