# flake8: noqa
# done for the mocked respose,
# everything else is linted and tested
import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class ApiVoidAnalyzer(classes.ObservableAnalyzer):
    url = "https://endpoint.apivoid.com"
    _api_key: str = None

    def update(self):
        pass

    def run(self):
        if self.observable_classification == self.ObservableTypes.DOMAIN.value:
            url = (
                self.url
                + f"""/domainbl/v1/pay-as-you-go/
                ?key={self._api_key}
                &host={self.observable_name}"""
            )
        elif self.observable_classification == self.ObservableTypes.IP.value:
            url = (
                self.url
                + f"""/iprep/v1/pay-as-you-go/
                ?key={self._api_key}
                &ip={self.observable_name}"""
            )
        elif self.observable_classification == self.ObservableTypes.URL.value:
            url = (
                self.url
                + f"""/urlrep/v1/pay-as-you-go/
                ?key={self._api_key}
                &url={self.observable_name}"""
            )
        r = requests.get(url)
        r.raise_for_status()
        return r.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "data": {
                                "report": {
                                    "ip": "2.57.122.0",
                                    "version": "v4",
                                    "blacklists": {
                                        "engines": {
                                            "0": {
                                                "engine": "0spam",
                                                "detected": False,
                                                "reference": "https://0spam.org/",
                                                "elapsed": "0.09",
                                            },
                                        },
                                        "detections": 7,
                                        "engines_count": 79,
                                        "detection_rate": "9%",
                                        "scantime": "1.35",
                                    },
                                    "information": {
                                        "reverse_dns": "",
                                        "continent_code": "EU",
                                        "continent_name": "Europe",
                                        "country_code": "RO",
                                        "country_name": "Romania",
                                        "country_currency": "RON",
                                        "country_calling_code": "40",
                                        "region_name": "Bucuresti",
                                        "city_name": "Bucharest",
                                        "latitude": 44.432301,
                                        "longitude": 26.10607,
                                        "isp": "Pptechnology Limited",
                                        "asn": "AS47890",
                                    },
                                    "anonymity": {
                                        "is_proxy": False,
                                        "is_webproxy": False,
                                        "is_vpn": False,
                                        "is_hosting": False,
                                        "is_tor": False,
                                    },
                                    "risk_score": {"result": 100},
                                }
                            },
                            "credits_remained": 24.76,
                            "estimated_queries": "309",
                            "elapsed_time": "2.58",
                            "success": True,
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
