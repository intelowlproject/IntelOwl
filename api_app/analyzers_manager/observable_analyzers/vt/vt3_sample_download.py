# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.mixins import VirusTotalv3AnalyzerMixin


class VirusTotalv3SampleDownload(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        return {"data": self._vt_download_file(self.observable_name).decode()}
