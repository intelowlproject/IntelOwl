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
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
