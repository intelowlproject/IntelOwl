# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
import subprocess
from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.analyzers_manager.file_analyzers.trufflehog import TruffleHog

from .base_test_class import BaseFileAnalyzerTest


class TestTruffleHog(BaseFileAnalyzerTest):
    analyzer_class = TruffleHog

    def get_extra_config(self):
        return {
            "verify": False,
            "only_verified": False,
        }

    def get_mocked_response(self):
        sample_secret = {
            "SourceMetadata": {"Data": {"Filesystem": {"file": "sample.py"}}},
            "SourceType": 14,
            "SourceName": "trufflehog - filesystem",
            "DetectorType": 17,
            "DetectorName": "AWS",
            "DecoderName": "PLAIN",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "RawV2": "",
            "Redacted": "AKIA************",
            "ExtraData": {"account": "123456789012"},
            "StructuredData": None,
        }
        stdout_text = json.dumps(sample_secret) + "\n"

        return [
            patch(
                "subprocess.run",
                return_value=subprocess.CompletedProcess(
                    args=["trufflehog", "filesystem", "file", "--json"],
                    returncode=0,
                    stdout=stdout_text,
                    stderr="",
                ),
            )
        ]

    def test_run_with_findings(self):
        """Test TruffleHog parsing when multiple secrets (verified and unverified) are found."""
        sample_findings = [
            {
                "DetectorName": "AWS",
                "Verified": True,
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "Redacted": "AKIA************",
            },
            {
                "DetectorName": "SlackWebhook",
                "Verified": False,
                "Raw": "https://hooks.slack.com/services/T00/B00/XXXX",
                "Redacted": "https://hooks.slack.com/services/T00/B00/****",
            },
        ]
        stdout_payload = "\n".join(json.dumps(f) for f in sample_findings) + "\n"

        analyzer = TruffleHog(config=MagicMock())
        analyzer._FileAnalyzer__filepath = "/tmp/testfile.txt"
        analyzer.filename = "testfile.txt"
        analyzer.verify = True
        analyzer.only_verified = False

        with patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["trufflehog", "filesystem", "/tmp/testfile.txt", "--json"],
                returncode=0,
                stdout=stdout_payload,
                stderr="",
            ),
        ) as mock_run:
            result = analyzer.run()

        mock_run.assert_called_once()
        self.assertEqual(result["secrets_found"], 2)
        self.assertEqual(result["verified_secrets"], 1)
        self.assertEqual(result["unverified_secrets"], 1)
        self.assertIn("AWS", result["detectors_triggered"])
        self.assertIn("SlackWebhook", result["detectors_triggered"])

    def test_run_no_secrets(self):
        """Test TruffleHog behavior when no secrets are found."""
        analyzer = TruffleHog(config=MagicMock())
        analyzer._FileAnalyzer__filepath = "/tmp/clean.txt"
        analyzer.filename = "clean.txt"
        analyzer.verify = False
        analyzer.only_verified = False

        with patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["trufflehog", "filesystem", "/tmp/clean.txt", "--json", "--no-verification"],
                returncode=0,
                stdout="",
                stderr="",
            ),
        ):
            result = analyzer.run()

        self.assertEqual(result["secrets_found"], 0)
        self.assertEqual(result["verified_secrets"], 0)
        self.assertEqual(result["unverified_secrets"], 0)
        self.assertEqual(result["detectors_triggered"], [])
        self.assertEqual(result["secrets"], [])

    def test_run_binary_not_found(self):
        """Test that AnalyzerRunException is raised if trufflehog binary is missing."""
        analyzer = TruffleHog(config=MagicMock())
        analyzer._FileAnalyzer__filepath = "/tmp/file.txt"
        analyzer.filename = "file.txt"
        analyzer.verify = False
        analyzer.only_verified = False

        with patch("subprocess.run", side_effect=FileNotFoundError):
            with self.assertRaises(AnalyzerRunException) as ctx:
                analyzer.run()
            self.assertIn("not installed or not in PATH", str(ctx.exception))

    def test_run_subprocess_error(self):
        """Test that AnalyzerRunException is raised if trufflehog execution fails."""
        analyzer = TruffleHog(config=MagicMock())
        analyzer._FileAnalyzer__filepath = "/tmp/file.txt"
        analyzer.filename = "file.txt"
        analyzer.verify = False
        analyzer.only_verified = False

        with patch(
            "subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="Fatal error scanning target",
            ),
        ):
            with self.assertRaises(AnalyzerRunException) as ctx:
                analyzer.run()
            self.assertIn("Fatal error scanning target", str(ctx.exception))
