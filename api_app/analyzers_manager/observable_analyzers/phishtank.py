# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import base64
import logging
from urllib.parse import urlparse

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from api_app.data_model_manager.enums import DataModelEvaluations

logger = logging.getLogger(__name__)

# A community-verified phishing hit is a strong malicious signal; an unverified
# listing is deliberately given reliability 5 — below MALICIOUS_RELIABILITY_FLOOR
# (6) — so it buckets to "suspicious" rather than "malicious".
_RELIABILITY_VERIFIED = 8
_RELIABILITY_UNVERIFIED = 5


class Phishtank(ObservableAnalyzer):
    _api_key_name: str

    def run(self):
        headers = {"User-Agent": "phishtank/IntelOwl"}
        observable_to_analyze = self.observable_name
        if self.observable_classification == Classification.DOMAIN:
            observable_to_analyze = "http://" + self.observable_name
        parsed = urlparse(observable_to_analyze)
        if not parsed.path:
            observable_to_analyze += "/"
        data = {
            "url": base64.b64encode(observable_to_analyze.encode("utf-8")),
            "format": "json",
        }
        # optional API key
        if not hasattr(self, "_api_key_name"):
            logger.warning(f"{self.__repr__()} -> Continuing w/o API key..")
        else:
            data["app_key"] = self._api_key_name
        try:
            resp = requests.post("https://checkurl.phishtank.com/checkurl/", data=data, headers=headers)
            resp.raise_for_status()
            result = resp.json()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        return result

    # Gate: the $-mapping would stamp MALICIOUS on any created model, so only a
    # real listing (in_database) may create one.
    def _do_create_data_model(self) -> bool:
        results = self.report.report.get("results") or {}
        return super()._do_create_data_model() and results.get("in_database") is True

    def _update_data_model(self, data_model) -> None:
        super()._update_data_model(data_model)
        results = self.report.report.get("results") or {}
        data_model.evaluation = DataModelEvaluations.MALICIOUS.value
        data_model.reliability = (
            _RELIABILITY_VERIFIED if results.get("verified") is True else _RELIABILITY_UNVERIFIED
        )
