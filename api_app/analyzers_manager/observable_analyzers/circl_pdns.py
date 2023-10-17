# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
from urllib.parse import urlparse

import pypdns

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponseNoOp, if_mock_connections, patch


class CIRCL_PDNS(classes.ObservableAnalyzer):
    _pdns_credentials: str

    def config(self):
        super().config()
        self.domain = self.observable_name
        if self.observable_classification == self.ObservableTypes.URL:
            self.domain = urlparse(self.observable_name).hostname
            # You should save CIRCL credentials with this template: "<user>|<pwd>"
        self.split_credentials = self._pdns_credentials.split("|")
        if len(self.split_credentials) != 2:
            raise AnalyzerRunException(
                "CIRCL credentials not properly configured."
                "Template to use: '<user>|<pwd>'"
            )

    def run(self):
        user, pwd = self.split_credentials
        pdns = pypdns.PyPDNS(basic_auth=(user, pwd))

        try:
            result = pdns.query(self.domain, timeout=5)
        except pypdns.errors.UnauthorizedError as e:
            raise AnalyzerRunException(
                f"Credentials are not valid: UnauthorizedError: {e}"
            )

        for result_item in result:
            keys_to_decode = ["time_first", "time_last"]
            for key_to_decode in keys_to_decode:
                time_extracted = result_item.get(key_to_decode, None)
                if time_extracted and isinstance(time_extracted, datetime.datetime):
                    result_item[key_to_decode] = time_extracted.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch("pypdns.PyPDNS", return_value=MockResponseNoOp({}, 200)),
            )
        ]
        return super()._monkeypatch(patches=patches)
