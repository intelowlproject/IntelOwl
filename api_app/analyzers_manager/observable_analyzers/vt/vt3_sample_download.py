# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.mixins import VirusTotalv3AnalyzerMixin
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class VirusTotalv3SampleDownload(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        return {"data": self._vt_download_file(self.observable_name).decode()}

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    side_effect=[
                        MockUpResponse(
                            {},
                            200,
                            text="hello world",
                        ),
                    ],
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
