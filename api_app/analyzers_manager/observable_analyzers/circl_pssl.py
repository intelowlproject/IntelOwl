# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import typing
from typing import Dict

import pypssl

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from certego_saas.apps.user.models import User


class CIRCL_PSSL(classes.ObservableAnalyzer):
    _pdns_credentials: str
    url = "https://www.circl.lu/"

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.__split_credentials = self._pdns_credentials.split("|")
        if len(self.__split_credentials) != 2:
            raise AnalyzerConfigurationException(
                "CIRCL credentials not properly configured. Template to use: '<user>|<pwd>'"
            )

    def run(self):
        user = self.__split_credentials[0]
        pwd = self.__split_credentials[1]

        pssl = pypssl.PyPSSL(base_url=self.url, basic_auth=(user, pwd))

        result = pssl.query(self.observable_name, timeout=5)

        certificates = []
        if result.get(self.observable_name, {}):
            certificates = list(result.get(self.observable_name).get("certificates", []))

        parsed_result = {"ip": self.observable_name, "certificates": []}
        for cert in certificates:
            subject = result.get(self.observable_name).get("subjects", {}).get(cert, {}).get("values", [])
            if subject:
                parsed_result["certificates"].append({"fingerprint": cert, "subject": subject[0]})

        return parsed_result

    def _get_health_check_url(self, user: User = None) -> typing.Optional[str]:
        return self.url
