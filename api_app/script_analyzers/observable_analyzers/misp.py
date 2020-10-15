import datetime
import pymisp

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class MISP(classes.ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "MISP_KEY")
        self.url_key_name = additional_config_params.get("url_key_name", "MISP_URL")
        self.url_name = secrets.get_secret(self.url_key_name)

    def run(self):
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"no MISP API key retrieved with name: {self.api_key_name}"
            )

        if not self.url_name:
            raise AnalyzerRunException(
                f"no MISP URL retrieved, key value: {self.url_key_name}"
            )

        misp_instance = pymisp.ExpandedPyMISP(self.url_name, api_key)
        # debug=True)

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
