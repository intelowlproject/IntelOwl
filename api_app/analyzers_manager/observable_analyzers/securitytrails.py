# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes


class SecurityTrails(classes.ObservableAnalyzer):
    base_url: str = "https://api.securitytrails.com/v1/"

    def set_params(self, params):
        self.analysis_type = params.get("securitytrails_analysis", "current")
        self.current_type = params.get("securitytrails_current_type", "details")
        self.history_analysis = params.get("securitytrails_history_analysis", "whois")
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        headers = {"apikey": self.__api_key, "Content-Type": "application/json"}

        if self.observable_classification == self.ObservableTypes.IP.value:
            uri = f"ips/nearby/{self.observable_name}"
        elif self.observable_classification == self.ObservableTypes.DOMAIN.value:
            if self.analysis_type == "current":
                if self.current_type == "details":
                    uri = f"domain/{self.observable_name}"
                elif self.current_type == "subdomains":
                    uri = f"domain/{self.observable_name}/subdomains"
                elif self.current_type == "tags":
                    uri = f"domain/{self.observable_name}/tags"
                else:
                    raise AnalyzerRunException(
                        "Not supported endpoint for current analysis."
                    )

            elif self.analysis_type == "history":
                if self.history_analysis == "whois":
                    uri = f"history/{self.observable_name}/whois"
                elif self.history_analysis == "dns":
                    uri = f"history/{self.observable_name}/dns/a"
                else:
                    raise AnalyzerRunException(
                        "Not supported endpoint for current analysis."
                    )

            else:
                raise AnalyzerRunException(
                    f"Not supported analysis type: {self.analysis_type}."
                )
        else:
            raise AnalyzerRunException(
                f"Not supported observable type: {self.observable_classification}. "
                "Supported are ip and domain."
            )

        try:
            response = requests.get(self.base_url + uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
