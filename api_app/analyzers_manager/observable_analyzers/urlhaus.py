# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from api_app.mixins import AbuseCHMixin

logger = logging.getLogger(__name__)


class URLHaus(AbuseCHMixin, ObservableAnalyzer):
    url = "https://urlhaus-api.abuse.ch/v1/"
    disable: bool = False  # optional

    def update(self) -> bool:
        pass

    def run(self):
        if self.disable:
            return {"disabled": True}

        headers = {"Accept": "application/json"}
        if self.observable_classification in [
            Classification.DOMAIN,
            Classification.IP,
        ]:
            uri = "host/"
            post_data = {"host": self.observable_name}
        elif self.observable_classification == Classification.URL:
            uri = "url/"
            post_data = {"url": self.observable_name}
        else:
            raise AnalyzerRunException(f"not supported observable type {self.observable_classification}.")

        response = requests.post(
            self.url + uri,
            data=post_data,
            headers=self.authentication_header | headers,
        )
        response.raise_for_status()

        return response.json()

    def _do_create_data_model(self) -> bool:
        return (
            super()._do_create_data_model()
            and self.report.report.get("query_status", "no_results") != "no_results"
        )
