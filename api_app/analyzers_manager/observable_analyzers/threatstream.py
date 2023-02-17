import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockResponse, if_mock_connections, patch


class Threatstream(classes.ObservableAnalyzer):
    base_url: str = "https://api.threatstream.com/api/"

    def set_params(self, params):
        self.analysis_type = params.get("threatstream_analysis")
        if self.analysis_type == "intelligence":
            self.limit = params.get("limit")
            self.must_active = params.get("must_active")
            self.minimal_confidence = params.get("minimal_confidence")
            self.modified_after = params.get("modified_after")
        self.__api_key = self._secrets["api_key_name"]
        self.__api_user = self._secrets["api_user_name"]

    def run(self):
        params = {}
        uri = ""
        if self.analysis_type == "intelligence":
            self.active = None
            if self.must_active:
                self.active = "active"
            params = {
                "value__contains": self.observable_name,
                "limit": self.limit,
                "status": self.active,
                "confidence__gt": self.minimal_confidence,
                "modified_ts__gte": self.modified_after,
            }  # If value = None don't enter in filter
            uri = "v2/intelligence/"
        elif self.analysis_type == "confidence":
            params = {"type": "confidence", "value": self.observable_name}
            uri = "v1/inteldetails/confidence_trend/"
        elif self.analysis_type == "passive_dns":
            if self.observable_classification == self.ObservableTypes.IP:
                uri = f"v1/pdns/ip/{self.observable_name}"
            elif self.observable_classification == self.ObservableTypes.DOMAIN:
                uri = f"v1/pdns/domain/{self.observable_name}"
            else:
                raise AnalyzerConfigurationException(
                    f"Observable {self.observable_classification} not supported."
                    "Currently supported are: ip, domain."
                )
        else:
            raise AnalyzerConfigurationException(
                f"Analysis type: {self.analysis_type} not supported."
                "Currently supported are: intelligence, confidence,passive_dns."
            )
        try:
            api_header = {"Authorization": f"apikey {self.__api_user}:{self.__api_key}"}
            response = requests.get(
                self.base_url + uri, params=params, headers=api_header
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        result = response.json()
        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
