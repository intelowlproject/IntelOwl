# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.observable_analyzers.vt.vt3_base import (
    VirusTotalv3AnalyzerMixin,
)

from tests.mock_utils import patch, if_mock_connections, MockResponse


class VirusTotalv3ScanFile(FileAnalyzer, VirusTotalv3AnalyzerMixin):
    def run(self):
        return self._vt_scan_file(self.md5)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse(
                        {"data": {"attributes": {"status": "completed"}}}, 200
                    ),
                ),
                patch(
                    "requests.post",
                    return_value=MockResponse(
                        {"scan_id": "scan_id_test", "data": {"id": "id_test"}}, 200
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
