# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.data_model_manager.enums import DataModelTags


class Shodan(classes.ObservableAnalyzer):
    url: str = "https://api.shodan.io/"

    shodan_analysis: str
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        if self.shodan_analysis == "search":
            params = {"key": self._api_key_name, "minify": True}
            uri = f"shodan/host/{self.observable_name}"
        elif self.shodan_analysis == "honeyscore":
            params = {
                "key": self._api_key_name,
            }
            uri = f"labs/honeyscore/{self.observable_name}"
        else:
            raise AnalyzerConfigurationException(
                f"analysis type: '{self.shodan_analysis}' not supported."
                "Supported are: 'search', 'honeyscore'."
            )

        try:
            response = requests.get(self.url + uri, params=params)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        if self.shodan_analysis == "honeyscore":
            return {"honeyscore": result}
        return result

    def _populate_host_fields(self, data_model, report: dict) -> None:
        if report.get("org"):
            data_model.org_name = report["org"]
        if report.get("isp"):
            data_model.isp = report["isp"]
        if report.get("country_code"):
            data_model.country_code = report["country_code"]

        asn = report.get("asn")
        if asn:
            try:
                data_model.asn = int(str(asn).upper().replace("AS", "").strip())
            except (ValueError, TypeError):
                pass

        if report.get("hostnames"):
            data_model.resolutions = report["hostnames"]

    def _populate_additional_info(self, data_model, report: dict) -> None:
        additional_info = {}
        if report.get("ports"):
            additional_info["ports"] = report["ports"]
        if report.get("vulns"):
            additional_info["vulnerabilities"] = report["vulns"]
        if additional_info:
            data_model.additional_info = additional_info

    def _populate_tags_and_evaluation(self, data_model, report: dict) -> None:
        shodan_tags = {str(t).lower() for t in (report.get("tags") or [])}
        tags_to_add = []
        if shodan_tags & {"vpn", "proxy", "tor"}:
            tags_to_add.append(DataModelTags.ANONYMIZER.value)
        if "tor" in shodan_tags:
            tags_to_add.append(DataModelTags.TOR_EXIT_NODE.value)
        if "scanner" in shodan_tags:
            tags_to_add.append(DataModelTags.SCANNER.value)
        if shodan_tags & {"malware", "c2", "botnet", "compromised"}:
            tags_to_add.append(DataModelTags.MALWARE.value)
            data_model.evaluation = self.EVALUATIONS.MALICIOUS.value
            data_model.reliability = 8
        if tags_to_add:
            data_model.tags = tags_to_add

    def _update_data_model(self, data_model) -> None:
        super()._update_data_model(data_model)
        report = self.report.report
        if self.shodan_analysis == "honeyscore":
            score = report.get("honeyscore") if isinstance(report, dict) else report
            data_model.additional_info = {"honeyscore": score}
            return

        if not isinstance(report, dict):
            return

        self._populate_host_fields(data_model, report)
        self._populate_additional_info(data_model, report)
        self._populate_tags_and_evaluation(data_model, report)
