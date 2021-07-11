# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import datetime
import pymisp

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager import classes


class MISP(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.ssl_check = params.get("ssl_check", True)
        self.debug = params.get("debug", False)
        self.__url_name = self._secrets["url_key_name"]
        self.__api_key = self._secrets["api_key_name"]

    def run(self):
        misp_instance = pymisp.PyMISP(
            url=self.__url_name,
            key=self.__api_key,
            ssl=self.ssl_check,
            debug=self.debug,
            timeout=5,
        )

        # we check only for events not older than 90 days and max 50 results
        now = datetime.datetime.now()
        date_from = now - datetime.timedelta(days=90)
        params = {
            # even if docs say to use "values",...
            # .. at the moment it works correctly only with "value"
            "value": self.observable_name,
            "type_attribute": [self.observable_classification],
            "date_from": date_from.strftime("%Y-%m-%d %H:%M:%S"),
            "limit": 50,
            "enforce_warninglist": True,
        }
        if self.observable_classification == "hash":
            params["type_attribute"] = ["md5", "sha1", "sha256"]
        result_search = misp_instance.search(**params)
        if isinstance(result_search, dict):
            errors = result_search.get("errors", [])
            if errors:
                raise AnalyzerRunException(errors)

        return {"result_search": result_search, "instance_url": self.url_name}
