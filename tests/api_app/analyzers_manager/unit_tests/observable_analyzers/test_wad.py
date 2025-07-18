from unittest.mock import patch

from wad.detection import Detector

from api_app.analyzers_manager.observable_analyzers.wad import WAD
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class WADTestCase(BaseAnalyzerTest):
    analyzer_class = WAD

    @staticmethod
    def get_mocked_response():
        return patch.object(
            Detector,
            "detect",
            return_value={
                "https://www.google.com/": [
                    {
                        "app": "Google Web Server",
                        "ver": "null",
                        "type": "Web Servers",
                    }
                ]
            },
        )

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}
