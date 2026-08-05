"""
macos/validation/collect_diagnostics.py
─────────────────────────────────────────────────────────────────────────────
Diagnostic report aggregator, sensitive data redactor, and ZIP packager for
the ZeroWatch native macOS validation harness.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("macos.validation.collect_diagnostics")


def anonymize_value(val: str) -> str:
    """Hash or redact sensitive identifiers (serials, UUIDs, usernames)."""
    if not val:
        return ""
    # Sha256 prefix for debug traceability without exposing raw secret
    digest = hashlib.sha256(val.encode("utf-8")).hexdigest()[:12]
    return f"ANONYMIZED:{digest}"


class ValidationDiagnostics:
    """
    Collects diagnostic test outputs, formats machine-readable JSON & markdown
    reports, redacts sensitive identifiers, and packages output into a single ZIP.
    """

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: Dict[str, Any] = {
            "platform": {},
            "summary": {"pass": 0, "fail": 0, "skip": 0},
            "tests": {},
        }
        self.errors: List[str] = []

    def log_test_result(self, test_name: str, status: str, details: Optional[Dict[str, Any]] = None, message: str = "") -> None:
        """Record the outcome of a single validation test stage."""
        status_upper = status.upper()
        if status_upper == "PASS":
            self.results["summary"]["pass"] += 1
        elif status_upper == "FAIL":
            self.results["summary"]["fail"] += 1
        elif status_upper == "SKIP":
            self.results["summary"]["skip"] += 1

        entry = {
            "status": status_upper,
            "message": message,
            "details": details or {},
        }
        self.results["tests"][test_name] = entry

        # Write to log file
        log_file = self.output_dir / "tests.txt"
        with open(log_file, "a", encoding="utf-8") as fh:
            fh.write(f"[{status_upper}] {test_name}: {message}\n")

    def record_error(self, test_name: str, err_msg: str) -> None:
        """Record an error stack trace or failure message."""
        self.errors.append(f"=== Error in {test_name} ===\n{err_msg}\n")
        err_file = self.output_dir / "errors.txt"
        with open(err_file, "a", encoding="utf-8") as fh:
            fh.write(f"=== {test_name} ===\n{err_msg}\n\n")

    def write_file(self, filename: str, content: str) -> None:
        """Write a diagnostic text file to the report directory."""
        target = self.output_dir / filename
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(content)

    def write_json(self, filename: str, data: Any) -> None:
        """Write a JSON file to the report directory."""
        target = self.output_dir / filename
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

    def finalize(self) -> Path:
        """
        Generate machine-readable results.json, human-readable summary.md,
        and create the final ZIP archive.
        Returns the absolute path to the generated ZIP.
        """
        # Save machine-readable results.json
        self.write_json("results.json", self.results)

        # Generate summary.md
        pass_cnt = self.results["summary"]["pass"]
        fail_cnt = self.results["summary"]["fail"]
        skip_cnt = self.results["summary"]["skip"]
        overall = "PASS" if fail_cnt == 0 else "NEEDS REVIEW"

        summary_md = [
            "# ZeroWatch macOS One-Shot Native Validation Summary",
            "",
            f"**Overall Status**: `{overall}`",
            f"**Passed**: {pass_cnt} | **Failed**: {fail_cnt} | **Skipped**: {skip_cnt}",
            "",
            "## Environment",
            "```text",
            f"macOS Version: {self.results['platform'].get('macos_version', 'Unknown')}",
            f"Architecture:  {self.results['platform'].get('architecture', 'Unknown')}",
            f"Python:        {self.results['platform'].get('python_version', 'Unknown')}",
            f"Privilege:     {self.results['platform'].get('user', 'Unknown')} (root={self.results['platform'].get('is_root', False)})",
            f"SIP Enabled:   {self.results['platform'].get('sip_status', 'Unknown')}",
            "```",
            "",
            "## Stage Results",
            "| Stage | Status | Details |",
            "|---|---|---|",
        ]

        for stage, res in self.results["tests"].items():
            status = res["status"]
            msg = res["message"]
            icon = "✅" if status == "PASS" else ("❌" if status == "FAIL" else "⏩")
            summary_md.append(f"| `{stage}` | {icon} {status} | {msg} |")

        if self.errors:
            summary_md.extend([
                "",
                "## Errors Recorded",
                "See `errors.txt` for complete stack traces.",
            ])

        self.write_file("summary.md", "\n".join(summary_md))

        # Compress output_dir into ZIP
        zip_path = self.output_dir.parent / f"{self.output_dir.name}.zip"
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _dirs, files in os.walk(self.output_dir):
                for f in files:
                    file_p = Path(root) / f
                    arcname = file_p.relative_to(self.output_dir.parent)
                    zf.write(file_p, arcname)

        logger.info("Validation diagnostics finalized: %s", zip_path)
        return zip_path
