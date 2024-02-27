# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime

import pymisp
from django.conf import settings

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockResponseNoOp, if_mock_connections, patch


class MISP(classes.ObservableAnalyzer):
    _api_key_name: str
    _url_key_name: str

    ssl_check: bool
    self_signed_certificate: bool
    debug: bool
    from_days: int
    limit: int
    enforce_warninglist: bool
    filter_on_type: bool
    strict_search: bool
    timeout: int
    published: bool
    metadata: bool

    def update(self):
        pass

    def run(self):
        # this allows self-signed certificates to be used
        ssl_param = (
            f"{settings.PROJECT_LOCATION}/configuration/misp_ssl.crt"
            if self.ssl_check and self.self_signed_certificate
            else self.ssl_check
        )
        misp_instance = pymisp.PyMISP(
            url=self._url_key_name,
            key=self._api_key_name,
            ssl=ssl_param,
            debug=self.debug,
            timeout=self.timeout,
        )
        now = datetime.datetime.now()
        date_from = now - datetime.timedelta(days=self.from_days)
        params = {
            "limit": self.limit,
            "enforce_warninglist": self.enforce_warninglist,
            "published": self.published,
            "metadata": self.metadata,
        }

        if self.strict_search:
            params["value"] = self.observable_name
        else:
            string_wildcard = f"%{self.observable_name}%"
            params["searchall"] = string_wildcard

        if self.from_days != 0:
            params["date_from"] = date_from.strftime("%Y-%m-%d %H:%M:%S")
        if self.filter_on_type:
            params["type_attribute"] = [self.observable_classification]
            if self.observable_classification == self.ObservableTypes.HASH:
                params["type_attribute"] = ["md5", "sha1", "sha256"]
            if self.observable_classification == self.ObservableTypes.IP:
                params["type_attribute"] = [
                    "ip-dst",
                    "ip-src",
                    "ip-src|port",
                    "ip-dst|port",
                    "domain|ip",
                ]
            elif self.observable_classification == self.ObservableTypes.DOMAIN:
                params["type_attribute"] = [self.observable_classification, "domain|ip"]
            elif self.observable_classification == self.ObservableTypes.HASH:
                params["type_attribute"] = ["md5", "sha1", "sha256"]
            elif self.observable_classification == self.ObservableTypes.URL:
                params["type_attribute"] = [self.observable_classification]
            elif self.observable_classification == self.ObservableTypes.GENERIC:
                pass
            else:
                raise AnalyzerConfigurationException(
                    f"Observable {self.observable_classification} not supported."
                    "Currently supported are: ip, domain, hash, url, generic."
                )

        result_search = misp_instance.search(**params)
        if isinstance(result_search, dict):
            errors = result_search.get("errors", [])
            if errors:
                raise AnalyzerRunException(errors)

        return {"result_search": result_search, "instance_url": self._url_key_name}

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch("pymisp.PyMISP", return_value=MockResponseNoOp({}, 200)),
            )
        ]
        return super()._monkeypatch(patches=patches)
