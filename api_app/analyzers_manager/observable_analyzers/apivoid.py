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
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
