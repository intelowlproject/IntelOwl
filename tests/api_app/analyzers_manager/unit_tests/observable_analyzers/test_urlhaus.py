# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.urlhaus import URLHaus
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class URLHausTestCase(BaseAnalyzerTest):
    analyzer_class = URLHaus

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.post",
            return_value=MockUpResponse(
                {
                    "query_status": "is_host",
                    "urlhaus_reference": "https://urlhaus.abuse.ch/host/8.8.8.8/",
                    "host": "8.8.8.8",
                    "urls": [
                        {
                            "id": "123456",
                            "url_status": "online",
                            "url": "http://8.8.8.8/malware.exe",
                            "threat": "malware_download",
                            "tags": ["exe", "malware"],
                            "date_added": "2024-01-01 00:00:00 UTC",
                        }
                    ],
                    "blacklists": {
                        "spamhaus_dbl": "not listed",
                        "surbl": "not listed",
                    },
                },
                200,
            ),
        )
