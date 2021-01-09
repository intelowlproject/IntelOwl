import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers import classes
from intel_owl import secrets


class WiGLE(classes.ObservableAnalyzer):
    base_url: str = "https://api.wigle.net"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "WIGLE_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)
        self.search_type = additional_config_params.get("search_type", "WiFi Network")

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
        if not self.__api_key:
            raise AnalyzerConfigurationException(
                f"No API key retrieved with name: {self.api_key_name}."
            )

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
                    f"search type: '{self.search_type}' not suported."
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
