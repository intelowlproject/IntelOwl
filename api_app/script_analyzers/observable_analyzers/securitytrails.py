import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class SecurityTrails(classes.ObservableAnalyzer):
    base_url: str = "https://api.securitytrails.com/v1/"

    def set_config(self, additional_config_params):
        self.analysis_type = additional_config_params.get(
            "securitytrails_analysis", "current"
        )
        self.current_type = additional_config_params.get(
            "securitytrails_current_type", "details"
        )
        self.history_analysis = additional_config_params.get(
            "securitytrails_history_analysis", "whois"
        )
        self.api_key_name = additional_config_params.get(
            "api_key_name", "SECURITYTRAILS_KEY"
        )

    def run(self):
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: '{self.api_key_name}'"
            )

        headers = {"apikey": api_key, "Content-Type": "application/json"}

        if self.observable_classification == "ip":
            uri = f"ips/nearby/{self.observable_name}"
        elif self.observable_classification == "domain":
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
