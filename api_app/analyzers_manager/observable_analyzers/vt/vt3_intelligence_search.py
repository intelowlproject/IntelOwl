# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.mixins import VirusTotalv3AnalyzerMixin


class VirusTotalv3Intelligence(ObservableAnalyzer, VirusTotalv3AnalyzerMixin):
    limit: int
    order_by: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        return self._vt_intelligence_search(self.observable_name, self.limit, self.order_by)
