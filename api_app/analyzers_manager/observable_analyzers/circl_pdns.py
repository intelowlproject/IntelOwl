# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import typing
from typing import Dict
from urllib.parse import urlparse

import pypdns

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from certego_saas.apps.user.models import User


class CIRCL_PDNS(classes.ObservableAnalyzer):
    _pdns_credentials: str
    url = "https://www.circl.lu/pdns/query"

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.domain = self.observable_name
        if self.observable_classification == Classification.URL:
            self.domain = urlparse(self.observable_name).hostname
            # You should save CIRCL credentials with this template: "<user>|<pwd>"
        self.split_credentials = self._pdns_credentials.split("|")
        if len(self.split_credentials) != 2:
            raise AnalyzerRunException(
                "CIRCL credentials not properly configured. Template to use: '<user>|<pwd>'"
            )

    def run(self):
        user, pwd = self.split_credentials
        pdns = pypdns.PyPDNS(url=self.url, basic_auth=(user, pwd))

        try:
            result = pdns.query(self.domain, timeout=5)
        except pypdns.errors.UnauthorizedError as e:
            raise AnalyzerRunException(f"Credentials are not valid: UnauthorizedError: {e}")

        for result_item in result:
            keys_to_decode = ["time_first", "time_last"]
            for key_to_decode in keys_to_decode:
                time_extracted = result_item.get(key_to_decode, None)
                if time_extracted and isinstance(time_extracted, datetime.datetime):
                    result_item[key_to_decode] = time_extracted.strftime("%Y-%m-%d %H:%M:%S")

        return result

    def _get_health_check_url(self, user: User = None) -> typing.Optional[str]:
        return self.url
