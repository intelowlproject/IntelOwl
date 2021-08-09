# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer
from .vt3_base import VirusTotalv3AnalyzerMixin

from tests.mock_utils import if_mock_connections, patch, MockResponse


class VirusTotalv3(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    def run(self):
        result = self._vt_get_report(
            self.observable_classification,
            self.observable_name,
        )

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    side_effect=[
                        # for _vt_get_report
                        MockResponse(
                            {
                                "data": {
                                    "attributes": {
                                        "status": "completed",
                                        "last_analysis_results": {"test": "test"},
                                        # must be earlier than 30 days ago
                                        "last_analysis_date": 1590000000,
                                    }
                                }
                            },
                            200,
                        ),
                        # for _vt_scan_file
                        MockResponse(
                            {
                                "data": {
                                    "attributes": {
                                        "status": "completed",
                                    }
                                }
                            },
                            200,
                        ),
                        # for /behaviour_summary
                        MockResponse({}, 200),
                        # for /sigma_analyses
                        MockResponse({}, 200),
                    ],
                ),
                patch(
                    "requests.post",
                    # for _vt_scan_file
                    return_value=MockResponse(
                        {"scan_id": "scan_id_test", "data": {"id": "id_test"}}, 200
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
