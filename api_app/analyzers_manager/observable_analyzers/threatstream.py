# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.choices import Classification


class Threatstream(classes.ObservableAnalyzer):
    url: str = "https://api.threatstream.com/api/"

    threatstream_analysis: str
    limit: str
    must_active: bool
    minimal_confidence: str
    modified_after: str

    _api_key_name: str
    _api_user_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        params = {}
        uri = ""
        if self.threatstream_analysis == "intelligence":
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
        elif self.threatstream_analysis == "confidence":
            params = {"type": "confidence", "value": self.observable_name}
            uri = "v1/inteldetails/confidence_trend/"
        elif self.threatstream_analysis == "passive_dns":
            if self.observable_classification == Classification.IP:
                uri = f"v1/pdns/ip/{self.observable_name}"
            elif self.observable_classification == Classification.DOMAIN:
                uri = f"v1/pdns/domain/{self.observable_name}"
            else:
                raise AnalyzerConfigurationException(
                    f"Observable {self.observable_classification} not supported. "
                    "Currently supported are: ip, domain."
                )
        else:
            raise AnalyzerConfigurationException(
                f"Analysis type: {self.threatstream_analysis} not supported. "
                "Currently supported are: intelligence, confidence, passive_dns."
            )
        try:
            api_header = {"Authorization": f"apikey {self._api_user_name}:{self._api_key_name}"}
            response = requests.get(self.url + uri, params=params, headers=api_header)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)
        result = response.json()
        return result
