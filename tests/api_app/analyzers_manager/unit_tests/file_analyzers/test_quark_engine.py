from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.quark_engine import QuarkEngine

from .base_test_class import BaseFileAnalyzerTest


class TestQuarkEngine(BaseFileAnalyzerTest):
    analyzer_class = QuarkEngine

    def get_extra_config(self):
        return {}

    def get_mocked_response(self):
        # Mock the Report class and its methods
        mock_report = MagicMock()
        mock_json_report = {
            "crimes": [
                {
                    "crime": "Send SMS",
                    "weight": 50,
                    "confidence": "80%",
                    "permissions": ["android.permission.SEND_SMS"],
                    "api": [
                        {
                            "class": "Landroid/telephony/SmsManager",
                            "method": "sendTextMessage",
                        }
                    ],
                    "register": [{"class": "Lcom/example/MainActivity", "method": "onCreate"}],
                }
            ],
            "total_score": 50,
            "summary": {"threat_level": "Medium", "total_crimes": 1},
        }
        mock_report.get_report.return_value = mock_json_report

        return [
            # Mock the Report class from where it's actually imported
            patch("quark.report.Report", return_value=mock_report),
            # Mock the DIR_PATH from where it's actually imported
            patch("quark.config.DIR_PATH", "/mock/rules/path"),
        ]
