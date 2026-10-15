import re

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from api_app.choices import Classification


class HudsonRock(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for hudson rock
    """

    url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

    def run(self):
        response = {}
        if self.observable_classification == Classification.IP:
            # GET /api/json/v2/osint-tools/search-by-ip?ip=

            response = requests.get(
                self.url + "/search-by-ip",
                params={"ip": self.observable_name},
            )

        elif self.observable_classification == Classification.DOMAIN:
            # GET /api/json/v2/osint-tools/search-by-domain?domain=
            response = requests.get(
                self.url + "/search-by-domain",
                params={"domain": self.observable_name},
            )

        elif self.observable_classification == Classification.GENERIC:
            # GET /api/json/v2/osint-tools/search-by-email?email=
            regex = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
            if re.fullmatch(regex, self.observable_name):
                response = requests.get(
                    self.url + "/search-by-email",
                    params={"email": self.observable_name},
                )
            else:
                raise AnalyzerConfigurationException(
                    f"observable '{self.observable_name}' is not a valid email. "
                    f"GENERIC type only supports email observables for HudsonRock"
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
