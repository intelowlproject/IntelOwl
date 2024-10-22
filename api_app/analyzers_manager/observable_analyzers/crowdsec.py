# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests
from django.conf import settings

from api_app.analyzers_manager.classes import ObservableAnalyzer, logger
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


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
        return super()._do_create_data_model() and not self.report.report.get(
            "not_fount", False
        )

    def _update_data_model(self, data_model):
        from api_app.analyzers_manager.models import AnalyzerReport

        self.report: AnalyzerReport
        super()._update_data_model(data_model)
        external_refs = []
        link = self.report.report.get("link", None)
        if link:
            external_refs.append(link)
        references = self.report.report.get("references", [])
        for reference in references:
            refs = reference.get("references", [])
            external_refs.extend(refs)
        external_references = getattr(data_model, "external_references")
        external_references.set(external_refs)

        highest_total_score = max(
            [
                values["total"]
                for key, values in self.report.report.get("scores", {}).items()
            ],
            default=0,
        )
        if highest_total_score <= 1:
            data_model.evaluation = self.report.data_model_class.EVALUATIONS.INFO.value
        elif 1 < highest_total_score <= 3:
            highest_trust_score = max(
                [
                    values["trust"]
                    for key, values in self.report.report.get("scores", {}).items()
                ]
            )
            if highest_trust_score >= 4:
                data_model.evaluation = (
                    self.report.data_model_class.EVALUATIONS.MALICIOUS.value
                )
            else:
                data_model.evaluation = (
                    self.report.data_model_class.EVALUATIONS.SUSPICIOUS.value
                )
        elif 3 < highest_total_score <= 5:
            data_model.evaluation = (
                self.report.data_model_class.EVALUATIONS.MALICIOUS.value
            )
        else:
            logger.error(f"unexpected score: {highest_total_score}")

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "behaviors": [
                                {
                                    "name": "http:exploit",
                                    "label": "HTTP Exploit",
                                    "description": "bla bla",
                                }
                            ]
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
