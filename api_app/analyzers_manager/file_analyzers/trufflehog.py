# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import logging
import subprocess

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class TruffleHog(FileAnalyzer):
    verify: bool = False
    only_verified: bool = False

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> dict:
        """Scan the uploaded file for secrets and credentials using TruffleHog."""
        cmd = [
            "trufflehog",
            "filesystem",
            self.filepath,
            "--json",
        ]

        if not self.verify:
            cmd.append("--no-verification")

        if self.only_verified:
            cmd.append("--only-verified")

        logger.info(f"Running TruffleHog on {self.filename} (verify={self.verify})")

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False,
            )
        except FileNotFoundError:
            logger.error("TruffleHog executable not found in system PATH")
            raise AnalyzerRunException("TruffleHog executable is not installed or not in PATH.")

        if process.returncode != 0 and not process.stdout:
            stderr = process.stderr.strip() if process.stderr else "Unknown error"
            logger.error(f"TruffleHog failed for {self.filename}: {stderr}")
            raise AnalyzerRunException(f"TruffleHog execution failed: {stderr}")

        findings = []
        detectors = set()

        for line in process.stdout.splitlines():
            clean_line = line.strip()
            if not clean_line:
                continue
            try:
                finding = json.loads(clean_line)
                findings.append(finding)
                detector_name = finding.get("DetectorName")
                if detector_name:
                    detectors.add(detector_name)
            except json.JSONDecodeError:
                logger.warning(f"Failed to parse TruffleHog NDJSON line: {clean_line}")
                continue

        verified_count = sum(1 for f in findings if f.get("Verified", False))
        unverified_count = len(findings) - verified_count

        return {
            "secrets_found": len(findings),
            "verified_secrets": verified_count,
            "unverified_secrets": unverified_count,
            "detectors_triggered": sorted(detectors),
            "secrets": findings,
        }
