# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import pypssl

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException
from tests.mock_utils import MockResponseNoOp, if_mock_connections, patch


class CIRCL_PSSL(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.__credentials = self._secrets["pdns_credentials"]
        if not self.__credentials:
            raise AnalyzerConfigurationException(
                "No secret retrieved for `pdns_credentials`."
            )
        self.__split_credentials = self.__credentials.split("|")
        if len(self.__split_credentials) != 2:
            raise AnalyzerConfigurationException(
                "CIRCL credentials not properly configured."
                "Template to use: '<user>|<pwd>'"
            )

    def run(self):
        user = self.__split_credentials[0]
        pwd = self.__split_credentials[1]

        pssl = pypssl.PyPSSL(basic_auth=(user, pwd))

        result = pssl.query(self.observable_name, timeout=5)

        certificates = []
        if result.get(self.observable_name, {}):
            certificates = list(
                result.get(self.observable_name).get("certificates", [])
            )

        parsed_result = {"ip": self.observable_name, "certificates": []}
        for cert in certificates:
            subject = (
                result.get(self.observable_name)
                .get("subjects", {})
                .get(cert, {})
                .get("values", [])
            )
            if subject:
                parsed_result["certificates"].append(
                    {"fingerprint": cert, "subject": subject[0]}
                )

        return parsed_result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch("pypssl.PyPSSL", return_value=MockResponseNoOp({}, 200)),
            )
        ]
        return super()._monkeypatch(patches=patches)
