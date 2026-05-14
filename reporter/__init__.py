from .dedupe import dedupe_report_document, dedupe_vulnerabilities, full_report_path
from .generator import ReportGenerator

__all__ = [
    "ReportGenerator",
    "dedupe_report_document",
    "dedupe_vulnerabilities",
    "full_report_path",
]
