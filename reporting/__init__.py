"""Reporters: JSON and self-contained HTML dashboards."""

from .html_report import write_html_report
from .json_report import build_report, write_json_report

__all__ = ["build_report", "write_json_report", "write_html_report"]
