import logging
from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.bbot import BBOT
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class BBOTTestCase(BaseAnalyzerTest):
    analyzer_class = BBOT

    def setUp(self):
        # Suppress logging for cleaner test output
        logging.getLogger("api_app.analyzers_manager.observable_analyzers.bbot").setLevel(logging.CRITICAL)

    @staticmethod
    def get_mocked_response():
        return patch(
            "api_app.analyzers_manager.observable_analyzers.bbot.BBOT._docker_run",
            return_value={
                "success": True,
                "report": {
                    "events": [
                        {
                            "id": "SCAN:7804fe5d0d26eec716926da9a4002d4ceb171300",
                            "name": "test_scan",
                            "status": "FINISHED",
                            "target": {
                                "seeds": ["example.com"],
                                "whitelist": ["example.com"],
                            },
                            "duration": "30 seconds",
                            "duration_seconds": 30.0,
                        }
                    ],
                    "json_output": [],
                },
            },
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {
            "presets": ["web-basic"],
            "modules": ["httpx"],
        }
