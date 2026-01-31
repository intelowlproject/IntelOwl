import logging
import re

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.choices import Classification

logger = logging.getLogger(__name__)


class HudsonRock(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for hudson rock
    """

    compromised_since: str = None  # for IP/DOMAIN
    compromised_until: str = None  # for IP/DOMAIN
    page: int = None  # for IP/LOGIN/DOMAIN
    added_since: str = None  # for IP/DOMAIN
    added_until: str = None  # for IP/DOMAIN
    installed_software: bool = None  # for IP/LOGIN/DOMAIN
    sort_by: str = None  # for LOGIN
    domain_cred_type: str = None  # for DOMAIN
    domain_filtered: bool = None  # for DOMAIN
    third_party_domains: bool = None  # for DOMAIN

    _api_key_name: str

    url = "https://cavalier.hudsonrock.com/api/json/v2"

    def get_param_url(self, valid_params):
        param_url = ""
        params = {
            "compromised_since": self.compromised_since,
            "compromised_until": self.compromised_until,
            "page": self.page,
            "added_since": self.added_since,
            "added_until": self.added_until,
            "installed_software": self.installed_software,
            "sortby": self.sort_by,
            "type": self.domain_cred_type,
            "filtered": self.domain_filtered,
            "third_party_domains": self.third_party_domains,
        }
        for param, value in params.items():
            if param in valid_params and value:
                param_url += f"&{param}={value}"

        return "?" + param_url

    def run(self):
        response = {}
        headers = {
            "api-key": self._api_key_name,
            "Content-Type": "application/json",
        }
        if self.observable_classification == Classification.IP:
            url = (
                self.url
                + "/search-by-ip"
                + self.get_param_url(
                    [
                        "compromised_since",
                        "compromised_until",
                        "page",
                        "added_since",
                        "added_until",
                        "installed_software",
                    ]
                )
            )
            response = requests.post(url, headers=headers, json={"ip": self.observable_name})

        elif self.observable_classification == Classification.DOMAIN:
            url = (
                self.url
                + "/search-by-domain"
                + self.get_param_url(
                    [
                        "compromised_since",
                        "compromised_until",
                        "page",
                        "added_since",
                        "added_until",
                        "installed_software",
                        "type",
                        "filtered",
                        "third_party_domains",
                    ]
                )
            )
            response = requests.post(url, headers=headers, json={"domains": [self.observable_name]})

        elif self.observable_classification == Classification.GENERIC:
            # checking for email
            regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
            if re.fullmatch(regex, self.observable_name):
                url = (
                    self.url
                    + "/search-by-login"
                    + self.get_param_url(["sortby", "page", "installed_software"])
                )
                response = requests.post(url, headers=headers, json={"login": self.observable_name})
        else:
            raise AnalyzerConfigurationException(
                f"Invalid observable type {self.observable_classification}"
                + f"{self.observable_name} for HudsonRock"
            )
        response.raise_for_status()
        return response.json()

    def update(self) -> bool:
        pass
