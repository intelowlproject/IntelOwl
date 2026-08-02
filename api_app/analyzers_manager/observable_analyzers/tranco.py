# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from urllib.parse import urlparse

import requests

from api_app.analyzers_manager import classes
from api_app.choices import Classification
from api_app.data_model_manager.enums import DataModelEvaluations

# Popularity is weak positive evidence, so Tranco's reliability caps at 4 —
# strictly below the malicious detectors (6–8) so a popular-but-flagged domain
# still reconciles to malicious, and it never reaches the "trusted" bucket (>=8).
_RANK_TOP = 10_000
_RANK_POPULAR = 100_000
_RELIABILITY_TOP = 4
_RELIABILITY_POPULAR = 3
_RELIABILITY_RANKED = 2


class Tranco(classes.ObservableAnalyzer):
    url: str = "https://tranco-list.eu/api/ranks/domain/"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        observable_to_analyze = self.observable_name
        if self.observable_classification == Classification.URL:
            observable_to_analyze = urlparse(self.observable_name).hostname

        url = self.url + observable_to_analyze
        response = requests.get(url)
        response.raise_for_status()

        return response.json()

    def _do_create_data_model(self) -> bool:
        rank = self.report.report.get("rank")
        return super()._do_create_data_model() and isinstance(rank, int) and rank > 0

    def _update_data_model(self, data_model) -> None:
        super()._update_data_model(data_model)
        rank = self.report.report.get("rank")
        data_model.evaluation = DataModelEvaluations.TRUSTED.value
        if rank <= _RANK_TOP:
            data_model.reliability = _RELIABILITY_TOP
        elif rank <= _RANK_POPULAR:
            data_model.reliability = _RELIABILITY_POPULAR
        else:
            data_model.reliability = _RELIABILITY_RANKED
