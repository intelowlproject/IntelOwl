from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.blint_scan import BlintAnalyzer
from tests.api_app.analyzers_manager.unit_tests.file_analyzers.base_test_class import (
    BaseFileAnalyzerTest,
)


class BlintTestCase(BaseFileAnalyzerTest):
    analyzer_class = BlintAnalyzer

    @staticmethod
    def get_mocked_response():
        # Create mock findings data
        mock_findings = [
            {
                "rule_id": "SEC001",
                "severity": "HIGH",
                "message": "Potential buffer overflow in strcpy usage",
                "file": "main.c",
                "line": 42,
                "column": 10,
                "type": "security",
            },
            {
                "rule_id": "SEC002",
                "severity": "MEDIUM",
                "message": "Use of deprecated function gets()",
                "file": "utils.c",
                "line": 15,
                "column": 5,
                "type": "security",
            },
        ]

        # Create mock reviews data
        mock_reviews = [
            {
                "category": "memory_safety",
                "description": "Manual review needed for pointer arithmetic",
                "priority": "high",
                "file": "core.c",
                "function": "parse_buffer",
            },
            {
                "category": "cryptography",
                "description": "Verify encryption implementation",
                "priority": "medium",
                "file": "crypto.c",
                "function": "encrypt_data",
            },
        ]

        # Create mock fuzzables data
        mock_fuzzables = [
            {
                "function": "process_input",
                "parameters": ["user_data", "buffer_size"],
                "file": "input.c",
                "line": 28,
                "risk_level": "high",
                "input_type": "string",
            },
            {
                "function": "parse_config",
                "parameters": ["config_file"],
                "file": "config.c",
                "line": 67,
                "risk_level": "medium",
                "input_type": "file",
            },
        ]

        # Create mock AnalysisRunner
        mock_runner = MagicMock()
        mock_runner.start.return_value = (mock_findings, mock_reviews, mock_fuzzables)

        # Return list of patches - focusing on what actually matters for the test
        return [
            # Mock the main Blint analysis engine
            patch("blint.lib.runners.AnalysisRunner", return_value=mock_runner),
            # Mock file system operations to avoid actual directory creation/deletion
            patch("api_app.analyzers_manager.file_analyzers.blint_scan.os.mkdir"),
            patch("api_app.analyzers_manager.file_analyzers.blint_scan.shutil.rmtree"),
            patch("api_app.analyzers_manager.file_analyzers.blint_scan.set_permissions"),
            patch("api_app.analyzers_manager.file_analyzers.blint_scan.logger"),
        ]
