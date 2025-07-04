from pathlib import Path
from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.feodo_tracker import Feodo_Tracker
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class FeodoTrackerTestCase(BaseAnalyzerTest):
    analyzer_class = Feodo_Tracker

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                [
                    {
                        "ip_address": "196.218.123.202",
                        "port": 13783,
                        "status": "offline",
                        "hostname": "host-196.218.123.202-static.tedata.net",
                        "as_number": 8452,
                        "as_name": "TE-AS TE-AS",
                        "country": "EG",
                        "first_seen": "2023-10-23 17:04:20",
                        "last_online": "2024-02-06",
                        "malware": "Pikabot",
                    }
                ],
                200,
            ),
        )

    @classmethod
    def get_extra_config(cls):
        # Force using mock data and bypass update
        return {
            "use_recommended_url": True,
            "update_on_run": False,
        }

    def setUp(self):
        super().setUp()
        # Pre-create the recommended database file with mock data
        data = [
            {
                "ip_address": "196.218.123.202",
                "port": 13783,
                "status": "offline",
                "hostname": "host-196.218.123.202-static.tedata.net",
                "as_number": 8452,
                "as_name": "TE-AS TE-AS",
                "country": "EG",
                "first_seen": "2023-10-23 17:04:20",
                "last_online": "2024-02-06",
                "malware": "Pikabot",
            }
        ]
        db_location = self.analyzer_class.recommend_locations[0]
        Path(db_location).parent.mkdir(parents=True, exist_ok=True)
        with open(db_location, "w", encoding="utf-8") as f:
            import json

            json.dump(data, f)
