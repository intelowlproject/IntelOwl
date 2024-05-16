# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class WiGLE(classes.ObservableAnalyzer):
    url: str = "https://api.wigle.net"

    _api_key_name: str
    search_type: str

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

        if self.search_type == "WiFi Network":
            uri = f"/api/v3/detail/wifi/{self.args.get('wifiNetworkId')}"
        elif self.search_type == "CDMA Network":
            uri = (
                f"/api/v3/detail/cell/CDMA/{self.args.get('sid')}/"
                f"{self.args.get('nid')}/{self.args.get('bsid')}"
            )
        elif self.search_type == "Bluetooth Network":
            uri = f"/api/v3/detail/bt/{self.args.get('btNetworkId')}"
        elif self.search_type == "GSM/LTE/WCDMA Network":
            uri = (
                "/api/v3/detail/cell/"
                f"{self.args.get('type')}/{self.args.get('operator')}/"
                f"{self.args.get('lac')}/{self.args.get('cid')}"
            )
        else:
            raise AnalyzerConfigurationException(
                f"search type: '{self.search_type}' not supported."
                "Supported are: 'WiFi Network', 'CDMA Network', "
                "'Bluetooth Network', 'GSM/LTE/WCDMA Network'"
            )

        response = requests.get(
            self.url + uri,
            headers={"Authorization": "Basic " + self._api_key_name},
        )
        response.raise_for_status()

        result = response.json()
        return result

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
