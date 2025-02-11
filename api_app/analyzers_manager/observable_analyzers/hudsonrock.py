import logging
import re

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.choices import Classification
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

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
            response = requests.post(
                url, headers=headers, json={"ip": self.observable_name}
            )

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
            response = requests.post(
                url, headers=headers, json={"domains": [self.observable_name]}
            )

        elif self.observable_classification == Classification.GENERIC:
            # checking for email
            regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
            if re.fullmatch(regex, self.observable_name):
                url = (
                    self.url
                    + "/search-by-login"
                    + self.get_param_url(["sortby", "page", "installed_software"])
                )
                response = requests.post(
                    url, headers=headers, json={"login": self.observable_name}
                )
        else:
            raise AnalyzerConfigurationException(
                f"Invalid observable type {self.observable_classification}"
                + f"{self.observable_name} for HudsonRock"
            )
        response.raise_for_status()
        return response.json()

    def update(self) -> bool:
        pass

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.post",
                    return_value=MockUpResponse(
                        {
                            "date_uploaded": "2019-11-07T04:38:32.024Z",
                            "stealer_family": "Vidar",
                            "antiviruses": "Not Found",
                            "employee_session_cookies": "null",
                            "date_compromised": "2019-11-04T13:33:47.000Z",
                            "credentials": [
                                {
                                    "type": "client",
                                    "url": "••••••••••••••",
                                    "domain": "disney.com",
                                    "username": "•••••••",
                                    "password": "••••••••",
                                }
                            ],
                            "stealer": "••••••••••••",
                            "employeeAt": ["••••••••••"],
                            "clientAt": [
                                "•••••••••••••••",
                                "•••••••••••",
                                "••••••••••••",
                                "•••••••••",
                                "•••••••••••••",
                                "••••••••••••••••••",
                                "•••••••••",
                                "•••••••••",
                                "••••••••••",
                                "•••••••••••",
                                "••••••••••••",
                                "••••••••••••••",
                                "•••••••••",
                                "•••••••••••••",
                                "••••••••",
                                "••••••••••••••••",
                                "••••••••••",
                                "••••••",
                                "•••••••••••",
                                "••••••••••••",
                                "••••••••••••",
                                "••••••••••",
                                "•••••••••••",
                                "••••••••••",
                                "•••••••••••••",
                                "••••••••••••••••",
                                "••••••••••••",
                                "•••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••",
                                "•••••••••",
                                "••••••••••••",
                                "••••••••",
                                "••••••••••",
                                "•••••••",
                                "•••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••••••••",
                                "••••••",
                                "••••••••••",
                                "••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••",
                                "•••••••••••",
                                "••••••",
                                "•••••••••",
                                "•••••••••",
                                "••••••••••",
                                "•••••••••••••••",
                            ],
                            "ip": "••••••••••••••",
                            "malware_path": "••••••••••••••",
                        },
                        {
                            "date_uploaded": "2019-11-06T21:51:35.676Z",
                            "stealer_family": "Vidar",
                            "antiviruses": "Not Found",
                            "employee_session_cookies": "null",
                            "date_compromised": "2019-11-03T20:39:11.000Z",
                            "credentials": [
                                {
                                    "type": "client",
                                    "url": "•••••••••••••••",
                                    "domain": "disney.com",
                                    "username": "•••",
                                    "password": "•••••••••",
                                }
                            ],
                            "stealer": "••••••••••••••••••••••••••••••••",
                            "employeeAt": ["•••••••••••", "••••••••••", "••••••"],
                            "clientAt": [],
                            "ip": "•••••••••••••",
                            "malware_path": "•••••••••••••••••••",
                        },
                        {
                            "date_uploaded": "2021-07-11T12:17:51.429Z",
                            "stealer_family": "RedLine",
                            "computer_name": "This PC",
                            "operating_system": "Windows 10 Home x64",
                            "antiviruses": "Norton 360",
                            "employee_session_cookies": "null",
                            "date_compromised": "2021-07-06T23:27:32.000Z",
                            "credentials": [
                                {
                                    "type": "client",
                                    "url": "••••••••",
                                    "domain": "disney.com",
                                    "username": "••••••",
                                    "password": "••••••••••",
                                }
                            ],
                            "stealer": "•••••••••••••••••••",
                            "employeeAt": ["•••••••••", "••••••••", "••••••••••"],
                            "clientAt": [
                                "•",
                                "•",
                                "••••",
                                "••••••••••••••",
                                "•••••••••",
                                "••••••••••",
                                "•••••••••••",
                                "•••••••••",
                                "••••••••••••",
                                "•••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••••••",
                                "••••••••••••",
                                "••••••••••",
                                "••••••••••••••••••",
                                "•••••••••••",
                                "••••••••••••",
                                "••••••••••••",
                                "••••••••",
                                "•••••••••••••••••",
                                "••••••••••••••••",
                                "••••••••••••••",
                                "•••••••••••",
                                "••••••••••••",
                                "•••••••••••••••••",
                                "•••••••••••••••••••••",
                                "•••••••••••••••••••",
                                "••••••••••••••••••••",
                                "•••••••••••••••••••••••",
                                "•••••••••••••",
                                "•••••••••••••••••••••",
                                "•••••••••••••••••••••••",
                                "••••••••",
                                "••••••••••••••••••••",
                                "•••••••••••••••••",
                                "•••••••••••••••••",
                                "•••••••••••",
                                "••••••••••",
                                "••••••••••••••",
                                "••••••••••••",
                                "•••••••••••",
                                "••••••••••",
                                "••••••••••",
                                "••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••",
                                "•••••••••",
                                "•••••••••••",
                                "•••••••",
                                "•••••••",
                                "••••••••••",
                                "••••••",
                                "••••••••",
                                "••••••••••",
                                "••••••••••••••••",
                                "••••••••••••",
                                "•••••••",
                                "•••••••••••••••",
                                "••••••••••",
                                "••••••••••••••••••",
                                "•••••••",
                                "••••••••",
                                "•••••••",
                                "•••••••••••••",
                                "•••••••••••",
                                "••••••••••",
                                "••••••••••••••••",
                                "•••••••••••",
                                "•••••••••••",
                                "•••••••••••••••",
                                "•••••••••••",
                                "•••••••",
                                "•••••••••••••",
                                "•••••••••••••",
                                "•••••••••••••",
                                "•••••••••••••••••",
                                "••••••••",
                                "••••••••••••",
                                "••••••••••••",
                                "••••••••",
                                "••••••••••••••",
                                "•••••••••••",
                                "•••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••",
                                "•••••••",
                                "•••••••••",
                                "••••••••••••",
                                "•••••••••••••••",
                                "•••••••••••••••",
                                "•••••••••",
                                "•••••••••••",
                                "••••••••",
                                "•••••••••••",
                                "••••••••••••••",
                                "•••••••••••",
                                "••••••••••••••",
                                "••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••••",
                                "••••••••",
                                "•••••••••••",
                                "•••••••••••",
                                "••••••••••••••••",
                                "•••",
                                "••••••••",
                                "•••••••••",
                            ],
                            "ip": "••••••••••••••",
                            "malware_path": "•••••••••••••",
                        },
                        {
                            "date_uploaded": "2021-05-06T05:58:56.299Z",
                            "stealer_family": "RedLine",
                            "computer_name": "jskho",
                            "operating_system": "Windows 10 Home x64",
                            "antiviruses": "Norton Security",
                            "employee_session_cookies": "null",
                            "date_compromised": "2021-05-06T01:31:09.000Z",
                            "credentials": [
                                {
                                    "type": "client",
                                    "url": "•••••••••••••••••",
                                    "domain": "disney.com",
                                    "username": "•••••••@gmail.com",
                                    "password": "••••••••",
                                }
                            ],
                            "stealer": "•••••••••••••••",
                            "employeeAt": [],
                            "clientAt": [
                                "••••••••••••••",
                                "•••••••••••••••••••",
                                "•••••••••••",
                                "•",
                                "•",
                                "••••",
                                "••••••••••••••••",
                                "••••••••••••••••••••",
                                "•••••••••••••••••••••",
                                "••••••••••••",
                                "••••••••••",
                                "•••••••••••••••",
                                "•••••••••",
                                "•••••",
                                "••••••••••••",
                                "•••••••••••••",
                                "••••••••••••••••••••••",
                                "•••••••••••••••••",
                                "•••••••••••••",
                                "•••••••••••",
                                "••••••••••••",
                                "••••••••",
                                "•••••••••",
                                "••••••••••••••",
                                "••••••",
                                "••••••••••••",
                                "••••••••••••••••",
                                "••••••••••••••",
                                "•••••••••••••••",
                                "•••••••••••••",
                                "•••••••••••",
                                "•••••••••••••••••••",
                                "•••••••••••••••••••",
                                "••••••••",
                                "••••••••••••••••••",
                                "•••••••••",
                                "•••••••••",
                                "•••••••••••••••••••••",
                                "•••••••••••••••••••••",
                                "•••••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••••••••",
                                "•••••••••••••••••••••",
                                "••••••••••",
                                "•••••••••••••••••••••",
                                "••••••••••••••••••••••••••",
                                "•••••••••••••",
                                "•••••••",
                                "••••••••••••••",
                                "••••••••••",
                                "••••••••••",
                                "•••••••••••",
                                "•••••••••",
                                "••••••••",
                                "••••••",
                                "••••••",
                                "•••••••••••",
                                "•••••••••••••••••••",
                                "•••••••••••••••",
                                "••••••••••",
                                "•••••••••••••••••",
                                "••••••••••••",
                                "••••••••••••••••••",
                                "•••••••••",
                                "••••••••••••",
                                "••••••••••••••••••",
                                "•••••••••",
                                "••••••",
                                "••••••••••",
                                "••••••••••••••••••",
                                "••••••••••",
                                "•••••••••••",
                                "••••••••••••",
                                "••••••••••••",
                                "•••••••••••••",
                                "••••••••••••••••••••",
                                "•••••",
                                "••••••••",
                                "•••••••••••",
                                "••••••••••••••",
                                "•••••••••••••••",
                                "•••••••••••••",
                                "•••••••••••••",
                                "••••••••••",
                                "••••••••••",
                                "••••••••••••••••",
                                "••••••••",
                                "•••••••••",
                                "••••••••••",
                                "•••••••••••••",
                                "••••••••••",
                                "•••••••••••",
                                "••••••••••••••",
                                "••••••••",
                                "•••••••••••••••••",
                                "••••••••••••••••••",
                                "•••••••••",
                                "•••••••••••••",
                                "••••••••••••••••••",
                                "•••••••••••••••",
                                "•••••••••",
                                "••••••••••••••",
                                "•••••••••••••••••",
                                "••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••",
                                "•••••••••••••••••••••••••",
                                "•••••••••••",
                                "••••••••••••",
                                "••••••••••••••",
                                "•••••••••",
                                "••••••••",
                                "••••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••",
                                "•••••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••••",
                                "•••••••••••••",
                                "••••••••••",
                                "•••••••••••••",
                                "•••••••••••••",
                                "••••••••••••",
                                "••••••••••••••••",
                                "••••••••••••",
                                "•••••••••",
                                "••••••••••••",
                                "••••••••••••",
                                "•••••••••••••••••",
                                "•••••••••••••",
                                "•••••••••••••",
                                "••••••••",
                                "•••••••••••••••••••••",
                                "••••••••••••",
                                "••••••••••••",
                                "••••••••••••",
                                "••••••••••••••••••••••",
                                "•••••••••",
                                "•••••••••••••••••••••",
                                "••••••••••••••",
                                "•••••••••••••••••••",
                                "•••••••••••••",
                                "•••••••••••",
                                "••••••••••",
                                "•••••••••••",
                                "•••••••••••",
                                "•••••••••••••••••••",
                                "••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••",
                                "••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••",
                                "••••••••••••••••",
                                "••••••••••••••••••••",
                                "••••••••••••",
                                "•••••••••••",
                                "••••••••••",
                                "•••••••••••••••••",
                                "•••••••••••••••••",
                                "•••••••••••••",
                                "•••••••••••••••",
                                "••••••••",
                                "••••••••••",
                                "•••••••••••••••••••••",
                                "•••••••••",
                                "•••••••••••",
                                "•••••••••••••••",
                                "•••••••••••",
                                "•••••••",
                                "••••••••",
                                "••••••••",
                                "•••••••••",
                                "•••••••••••••••",
                                "••••••••••••••••",
                                "••••••••••••••••••",
                                "•••••••••",
                                "••••••••••••••••",
                                "•••••••",
                                "•••",
                            ],
                            "ip": "•••••••••••••",
                            "malware_path": "••••••",
                        },
                        {
                            "date_uploaded": "2021-04-02T11:46:34.357Z",
                            "stealer_family": "RedLine",
                            "computer_name": "samih",
                            "operating_system": "Windows 10 Home x64",
                            "antiviruses": "Windows Defender",
                            "employee_session_cookies": "null",
                            "date_compromised": "2021-03-31T18:23:31.000Z",
                            "credentials": [
                                {
                                    "type": "client",
                                    "url": "",
                                    "domain": "disney.com",
                                    "username": "••••••••",
                                    "password": "••••••••••",
                                },
                                {
                                    "type": "client",
                                    "url": "•••••••••••••••••",
                                    "domain": "disney.com",
                                    "username": "••••••••",
                                    "password": "••••••••••",
                                },
                            ],
                            "stealer": "••••••••••••••••••••",
                            "employeeAt": [],
                            "clientAt": [
                                "•",
                                "•",
                                "••••",
                                "•••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••••••••••",
                                "••••••••••",
                                "•••••••••••",
                                "••••••",
                                "••••••••",
                                "••••••••••••",
                                "••••••••••",
                                "•••••••••",
                                "•••••••••••••••••••",
                                "••••••••••••••••••",
                                "••••••••••••",
                                "••••••••••",
                                "••••••••••",
                                "••••••••••",
                                "•••••••••••••••••",
                                "••••••••••",
                                "•••••••••••••",
                                "••••••••",
                                "••••••••••••••••••••••••••••",
                                "••••••••••••••••",
                                "•••••••••",
                                "•••",
                            ],
                            "ip": "••••••••••••••",
                            "malware_path": "•••••",
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
