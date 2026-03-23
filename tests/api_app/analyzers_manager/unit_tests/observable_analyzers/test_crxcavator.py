from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.crxcavator import CRXcavator
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class CRXcavatorTestCase(BaseAnalyzerTest):
    analyzer_class = CRXcavator

    @staticmethod
    def get_mocked_response():
        # Mock Chrome extension analysis report from CRXcavator
        mock_report = {
            "data": {
                "crx_id": "abcdefghijklmnopqrstuvwxyz123456",
                "name": "Example Extension",
                "version": "1.2.3",
                "description": "A sample Chrome extension for testing",
                "permissions": ["activeTab", "storage", "https://api.example.com/*"],
                "risk": {
                    "total": 850,
                    "metadata": 200,
                    "permissions": 300,
                    "content_scripts": 150,
                    "externally_connectable": 100,
                    "optional_permissions": 100,
                },
                "webstore": {
                    "last_updated": "2024-01-15",
                    "users": "50,000+",
                    "rating": 4.2,
                    "rating_users": 1250,
                },
                "manifest": {
                    "version": 2,
                    "permissions": ["activeTab", "storage"],
                    "content_scripts": [{"matches": ["https://*.example.com/*"], "js": ["content.js"]}],
                },
            },
            "status": "success",
        }

        return [patch("requests.get", return_value=MockUpResponse(mock_report, 200))]

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}
