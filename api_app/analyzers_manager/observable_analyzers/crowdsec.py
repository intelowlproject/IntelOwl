# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.data_model_manager.enums import DataModelTags

logger = logging.getLogger(__name__)


class Crowdsec(ObservableAnalyzer):
    _api_key_name: str
    url: str = "https://cti.api.crowdsec.net"

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {
            "x-api-key": self._api_key_name,
            "User-Agent": f"crowdsec-intelowl/{settings.VERSION}",
        }
        url = f"{self.url}/v2/smoke/{self.observable_name}"
        response = requests.get(url, headers=headers)
        if response.status_code == 404:
            result = {"not_found": True}
        else:
            response.raise_for_status()
            result = response.json()
        result["link"] = f"https://app.crowdsec.net/cti/{self.observable_name}"
        return result

    def _do_create_data_model(self):
        return super()._do_create_data_model() and not self.report.report.get("not_found", False)

    def _update_data_model(self, data_model):
        from api_app.analyzers_manager.models import AnalyzerReport

        self.report: AnalyzerReport
        super()._update_data_model(data_model)

        classifications = self.report.report.get("classifications", {}).get("classifications", [])
        for classification in classifications:
            label = classification.get("label", "")
            if label in ["Legit scanner", "Known Security Company", "Known CERT"]:
                data_model.evaluation = self.EVALUATIONS.TRUSTED.value
                data_model.reliability = 9
            elif label in ["Likely Botnet", "CrowdSec Community Blocklist"]:
                data_model.additional_info = {"classifications": classifications}
                data_model.evaluation = self.EVALUATIONS.MALICIOUS.value
                data_model.reliability = 3
            elif "Proxy" in label or "VPN" in label:
                data_model.tags = [DataModelTags.ANONYMIZER.value]
                data_model.evaluation = self.EVALUATIONS.TRUSTED.value
                data_model.reliability = 3
            elif label in ["TOR exit node"]:
                data_model.tags = [
                    DataModelTags.ANONYMIZER.value,
                    DataModelTags.TOR_EXIT_NODE.value,
                ]
                data_model.evaluation = self.EVALUATIONS.TRUSTED.value
                data_model.reliability = 2

        highest_total_score = max(
            (values["total"] for key, values in self.report.report.get("scores", {}).items()),
            default=0,
        )
        if data_model.evaluation != self.EVALUATIONS.TRUSTED.value:
            if highest_total_score <= 1:
                data_model.reliability = 8
            else:
                highest_trust_score = max(
                    values["trust"] for key, values in self.report.report.get("scores", {}).items()
                )
                data_model.reliability = min(highest_trust_score, 10)
