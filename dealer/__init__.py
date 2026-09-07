"""The Dealer — blue-team investigation reps you own end to end.

The loop: deal a case (sealed truth), investigate telemetry blind, submit a
verdict, get it graded, track your reps over time.

Public API:
    from dealer import deal, generate_telemetry, grade, GroundTruth, Verdict
"""
from .schema import GroundTruth, Verdict, SchemaError, load_ground_truth, load_verdict
from .grader import grade, Report, LineItem
from .catalog import deal, load_catalog, Scenario, DealtCase
from .telemetry import generate as generate_telemetry
from .history import record, stats, Stats

__version__ = "0.4.0"
__all__ = [
    "grade", "Report", "LineItem",
    "GroundTruth", "Verdict", "SchemaError",
    "load_ground_truth", "load_verdict",
    "deal", "load_catalog", "Scenario", "DealtCase",
    "generate_telemetry",
    "record", "stats", "Stats",
]
