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
    published: bool
    metadata: bool

    def update(self):
        pass

    def _handle_search_errors(self, errors):
        error_str = str(errors)
        if "restSearch" in error_str and "GET" in error_str:
            debug_info = (
                f" [debug: PyMISP version={pymisp.__version__},"
                f" ssl_check={self.ssl_check},"
                f" url={self._url_key_name}]"
                if self.debug
                else ""
            )
            raise AnalyzerRunException(
                f"MISP restSearch failed with a GET/POST mismatch error: {errors}. "
                "This is usually caused by an HTTP to HTTPS redirect stripping "
                "the POST body. Try changing your MISP URL from 'http://' to "
                "'https://' in the plugin configuration."
                " Also check that ssl_check matches your URL protocol."
                f"{debug_info}"
            )
        raise AnalyzerRunException(errors)

    def _get_ssl_parameter(self):
        """Determine the SSL parameter for PyMISP connection."""
        if self.ssl_check and self.self_signed_certificate:
            return f"{settings.PROJECT_LOCATION}/configuration/misp_ssl.crt"
        return self.ssl_check

    def _build_search_params(self):
        """Build search parameters for MISP API query."""
        now = datetime.datetime.now()
        date_from = now - datetime.timedelta(days=self.from_days)

        params = {
            "limit": self.limit,
        }

        if self.enforce_warninglist:
            params["enforce_warninglist"] = self.enforce_warninglist

        # https://pymisp.readthedocs.io/en/latest/modules.html#pymisp.PyMISP
        # fixme: this should be None as default but is False
        # so it's not possible to set it as False in this way.
        #  migration required
        if self.published:
            params["published"] = self.published

        if self.metadata:
            params["metadata"] = self.metadata

        if self.strict_search:
            params["value"] = self.observable_name
        else:
            params["searchall"] = f"%{self.observable_name}%"

        if self.from_days != 0:
            params["date_from"] = date_from.strftime("%Y-%m-%d %H:%M:%S")

        self._add_type_filters(params)

        return params

    def _add_type_filters(self, params):
        """Add type-specific attribute filters to search parameters."""
        if not self.filter_on_type:
            return

        if self.observable_classification == Classification.HASH:
            params["type_attribute"] = ["md5", "sha1", "sha256"]
        elif self.observable_classification == Classification.IP:
            params["type_attribute"] = [
                "ip-dst",
                "ip-src",
                "ip-src|port",
                "ip-dst|port",
                "domain|ip",
            ]
        elif self.observable_classification == Classification.DOMAIN:
            params["type_attribute"] = [
                self.observable_classification,
                "domain|ip",
            ]
        elif self.observable_classification == Classification.URL:
            params["type_attribute"] = [self.observable_classification]
        elif self.observable_classification == Classification.GENERIC:
            pass
        else:
            raise AnalyzerConfigurationException(
                f"Observable {self.observable_classification} not supported. "
                "Currently supported are: ip, domain, hash, url, generic."
            )

    def run(self):
        ssl_param = self._get_ssl_parameter()

        try:
            misp_instance = pymisp.PyMISP(
                url=self._url_key_name,
                key=self._api_key_name,
                ssl=ssl_param,
                debug=self.debug,
                timeout=self.timeout,
            )
        except Exception as e:
            raise AnalyzerRunException(f"MISP connection failed during initialization: {str(e)}")

        params = self._build_search_params()

        try:
            result_search = misp_instance.search(**params)
        except Exception as e:
            raise AnalyzerRunException(f"MISP search failed: {str(e)}")

        if isinstance(result_search, dict):
            errors = result_search.get("errors", [])
            if errors:
                self._handle_search_errors(errors)

        return {
            "result_search": result_search,
            "instance_url": self._url_key_name,
        }
