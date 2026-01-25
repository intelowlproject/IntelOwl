# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.mixins import VirusTotalv3AnalyzerMixin


class VirusTotalv3(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        result = self._vt_get_report(
            self.observable_classification,
            self.observable_name,
        )

        return result
