# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification


class SecurityTrails(classes.ObservableAnalyzer):
    url: str = "https://api.securitytrails.com/v1/"
    securitytrails_analysis: str
    securitytrails_current_type: str
    securitytrails_history_analysis: str
    _api_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {"apikey": self._api_key_name, "Content-Type": "application/json"}

        if self.observable_classification == Classification.IP:
            uri = f"ips/nearby/{self.observable_name}"
        elif self.observable_classification == Classification.DOMAIN:
            if self.securitytrails_analysis == "current":
                if self.securitytrails_current_type == "details":
                    uri = f"domain/{self.observable_name}"
                elif self.securitytrails_current_type == "subdomains":
                    uri = f"domain/{self.observable_name}/subdomains"
                elif self.securitytrails_current_type == "tags":
                    uri = f"domain/{self.observable_name}/tags"
                else:
                    raise AnalyzerRunException("Not supported endpoint for current analysis.")

            elif self.securitytrails_analysis == "history":
                if self.securitytrails_history_analysis == "whois":
                    uri = f"history/{self.observable_name}/whois"
                elif self.securitytrails_history_analysis == "dns":
                    uri = f"history/{self.observable_name}/dns/a"
                else:
                    raise AnalyzerRunException("Not supported endpoint for current analysis.")

            else:
                raise AnalyzerRunException(f"Not supported analysis type: {self.securitytrails_analysis}.")
        else:
            raise AnalyzerRunException(
                f"Not supported observable type: {self.observable_classification}. "
                "Supported are ip and domain."
            )

        try:
            response = requests.get(self.url + uri, headers=headers)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        return response.json()
