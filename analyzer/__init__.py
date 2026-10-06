"""Analyzer package - the brain of the Network Traffic Analyzer.

Modules
-------
``utils``      load captures, format bytes / durations, measure text width
``live``       live (online) capture straight from a network interface
``stats``      turn packets into statistics (one single pass)
``anomalies``  rule-based detection, one :class:`Finding` per suspicion
``ui``         premium terminal output (colors, glyphs, aligned tables)
``report``     save a text report and a CSV summary
"""

from analyzer import anomalies, live, report, stats, ui, utils  # noqa: F401

__all__ = ["anomalies", "live", "report", "stats", "ui", "utils"]
__version__ = "2.2.0"
