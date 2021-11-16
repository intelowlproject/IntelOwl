# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerConfigurationException, AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class WiGLE(classes.ObservableAnalyzer):
    base_url: str = "https://api.wigle.net"

    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        self.search_type = params.get("search_type", "WiFi Network")

    def __prepare_args(self):
        # Sample Argument: operator=001;type=GSM
        args = self.observable_name.split(";")
        self.args = {}
        for arg in args:
            try:
                key, value = arg.split("=")
            except ValueError:
                key = "wifiNetworkId"
                value = arg
            self.args[key] = value

    def run(self):
        self.__prepare_args()

        try:
            if self.search_type == "WiFi Network":
                uri = f"/api/v3/detail/wifi/{self.args.get('wifiNetworkId', None)}"
            elif self.search_type == "CDMA Network":
                uri = (
                    f"/api/v3/detail/cell/CDMA/{self.args.get('sid', None)}/"
                    f"{self.args.get('nid', None)}/{self.args.get('bsid', None)}"
                )
            elif self.search_type == "Bluetooth Network":
                uri = f"/api/v3/detail/bt/{self.args.get('btNetworkId', None)}"
            elif self.search_type == "GSM/LTE/WCDMA Network":
                uri = (
                    "/api/v3/detail/cell/"
                    f"{self.args.get('type', None)}/{self.args.get('operator', None)}/"
                    f"{self.args.get('lac', None)}/{self.args.get('cid', None)}"
                )
            else:
                raise AnalyzerConfigurationException(
                    f"search type: '{self.search_type}' not supported."
                    "Supported are: 'WiFi Network', 'CDMA Network', "
                    "'Bluetooth Network', 'GSM/LTE/WCDMA Network'"
                )

            response = requests.get(
                self.base_url + uri,
                headers={"Authorization": "Basic " + self.__api_key},
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
