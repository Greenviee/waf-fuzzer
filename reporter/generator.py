from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from fuzzer import EngineStats, Finding


class ReportGenerator:
    """
    Converts fuzzing engine statistics and findings into readable reports.
    """

    def __init__(self, stats: EngineStats, findings: list[Finding]) -> None:
        self.stats = stats
        self.findings = findings
        self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def print_cli_report(self) -> None:
        """
        Prints the scan result in a table-like CLI format.
        """
        table_width = 126
        severity_width = 10
        location_width = 10
        parameter_width = 14
        type_width = 34

        print("\n" + "=" * table_width)
        print("WAF Fuzzer Security Scan Report")
        print(f"Scan completed at: {self.timestamp}")
        print("=" * table_width)

        print("\n[1] Summary")
        print(f"  - queued:    {self.stats.queued}")
        print(f"  - completed: {self.stats.completed}")
        print(f"  - failures:  {self.stats.failures}")
        print(f"  - findings:  {self.stats.findings}")

        if not self.findings:
            print("\nNo findings were detected.")
            print("=" * table_width + "\n")
            return

        print("\n[2] Findings")
        print("-" * table_width)
        print(
            f"{'Severity':<{severity_width}} | {'Location':<{location_width}} | "
            f"{'Parameter':<{parameter_width}} | {'Type':<{type_width}} | Payload"
        )
        print("-" * table_width)

        for finding in self.findings:
            payload_obj = finding.payload
            severity = getattr(payload_obj, "risk_level", "HIGH")
            attack_type = getattr(payload_obj, "attack_type", "PotentialIssue")
            payload_value = getattr(payload_obj, "value", str(payload_obj))

            param_location = getattr(finding.surface, "param_location", "unknown")
            location_text = getattr(param_location, "name", str(param_location))

            display_payload = (
                payload_value[:37] + "..." if len(payload_value) > 40 else payload_value
            )
            display_type = (
                attack_type[: type_width - 3] + "..."
                if len(attack_type) > type_width
                else attack_type
            )
            print(
                f"{severity:<{severity_width}} | {location_text:<{location_width}} | "
                f"{finding.parameter:<{parameter_width}} | {display_type:<{type_width}} | "
                f"{display_payload}"
            )

        print("-" * table_width)
        print(f"Total findings: {len(self.findings)}")
        print("=" * table_width + "\n")

    def export_to_json(self, filepath: str = "scan_result.json") -> None:
        """
        Exports the scan result to a JSON file.
        """
        report_data: dict[str, Any] = {
            "metadata": {
                "scan_time": self.timestamp,
                "summary": {
                    "queued": self.stats.queued,
                    "completed": self.stats.completed,
                    "failures": self.stats.failures,
                    "findings": self.stats.findings,
                },
            },
            "vulnerabilities": [],
        }

        for finding in self.findings:
            payload_obj = finding.payload
            payload_value = getattr(payload_obj, "value", str(payload_obj))
            attack_type = getattr(payload_obj, "attack_type", "Unknown")
            severity = getattr(payload_obj, "risk_level", "high")
            description = getattr(payload_obj, "description", "")

            response = finding.response
            status_code = getattr(response, "status", 0)
            response_time = getattr(response, "elapsed_time", getattr(response, "elapsed", 0.0))
            error_log = getattr(response, "error", None)

            method = getattr(finding.surface.method, "name", str(finding.surface.method))
            location = getattr(
                getattr(finding.surface, "param_location", "unknown"),
                "name",
                str(getattr(finding.surface, "param_location", "unknown")),
            )

            report_data["vulnerabilities"].append(
                {
                    "target": {
                        "url": finding.surface.url,
                        "method": method,
                        "location": location,
                        "parameter": finding.parameter,
                    },
                    "attack_info": {
                        "payload_value": payload_value,
                        "type": attack_type,
                        "severity": severity,
                        "description": description,
                    },
                    "evidence": {
                        "status_code": status_code,
                        "response_time": round(float(response_time), 4),
                        "error_log": error_log,
                    },
                }
            )

        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(report_data, file, ensure_ascii=False, indent=2)

        print(f"report saved: {filepath}")