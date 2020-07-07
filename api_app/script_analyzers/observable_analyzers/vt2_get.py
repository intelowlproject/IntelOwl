import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets

vt_base = "https://www.virustotal.com/vtapi/v2/"


class VirusTotalv2(classes.ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "VT_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        return vt_get_report(
            self.__api_key, self.observable_name, self.observable_classification
        )


def vt_get_report(api_key, observable_name, observable_classification):
    params = {"apikey": api_key}
    if observable_classification == "domain":
        params["domain"] = observable_name
        uri = "domain/report"
    elif observable_classification == "ip":
        params["ip"] = observable_name
        uri = "ip-address/report"
    elif observable_classification == "url":
        params["resource"] = observable_name
        uri = "url/report"
    elif observable_classification == "hash":
        params["resource"] = observable_name
        params["allinfo"] = 1
        uri = "file/report"
    else:
        raise AnalyzerRunException(
            "not supported observable type {}. Supported are: hash, ip, domain and url"
            "".format(observable_classification)
        )

    try:
        response = requests.get(vt_base + uri, params=params)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)
    result = response.json()
    response_code = result.get("response_code", 1)
    if response_code == -1:
        raise AnalyzerRunException(f"response code -1. result:{result}")
    return result
