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
from api_app.choices import Classification


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
    timeout: int = 5
    published: bool = None
    metadata: bool

    def update(self):
        pass

    def _get_type_attributes(self) -> list:
        cls = self.observable_classification
        if cls == Classification.HASH:
            return ["md5", "sha1", "sha256"]
        if cls == Classification.IP:
            return [
                "ip-dst",
                "ip-src",
                "ip-src|port",
                "ip-dst|port",
                "domain|ip",
            ]
        if cls == Classification.DOMAIN:
            return [cls, "domain|ip"]
        if cls in [Classification.URL, Classification.GENERIC]:
            return [cls]

        raise AnalyzerConfigurationException(
            f"Observable {cls} not supported. Currently supported are: ip, domain, hash, url, generic."
        )

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
        }
        if self.enforce_warninglist:
            params["enforce_warninglist"] = self.enforce_warninglist
        # https://pymisp.readthedocs.io/en/latest/modules.html#pymisp.PyMISP
        if self.published is not None:
            params["published"] = self.published
        if self.metadata:
            params["metadata"] = self.metadata

        if self.strict_search:
            params["value"] = self.observable_name
        else:
            string_wildcard = f"%{self.observable_name}%"
            params["searchall"] = string_wildcard

        if self.from_days != 0:
            params["date_from"] = date_from.strftime("%Y-%m-%d %H:%M:%S")
        if self.filter_on_type:
            params["type_attribute"] = self._get_type_attributes()

        result_search = misp_instance.search(**params)
        if isinstance(result_search, dict):
            errors = result_search.get("errors", [])
            if errors:
                raise AnalyzerRunException(errors)

        return {"result_search": result_search, "instance_url": self._url_key_name}
