import requests

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets

vt_base = "https://www.virustotal.com/vtapi/v2/"


class VirusTotalv2(classes.ObservableAnalyzer):
    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "VT_KEY")

    def run(self):
        api_key = secrets.get_secret(self.api_key_name)
        if not api_key:
            raise AnalyzerRunException(
                f"No API key retrieved with name: {self.api_key_name}"
            )

        resp = vt_get_report(
            api_key, self.observable_name, self.observable_classification
        )

        resp_code = resp.get("response_code", 1)
        verbose_msg = resp.get("verbose_msg", "")
        if resp_code == -1 or "Invalid resource" in verbose_msg:
            self.report["errors"].append(verbose_msg)
            raise AnalyzerRunException(f"response code {resp_code}. response: {resp}")
        return resp


def vt_get_report(api_key, observable_name, obs_clsfn):
    params = {"apikey": api_key}
    if obs_clsfn == "domain":
        params["domain"] = observable_name
        uri = "domain/report"
    elif obs_clsfn == "ip":
        params["ip"] = observable_name
        uri = "ip-address/report"
    elif obs_clsfn == "url":
        params["resource"] = observable_name
        uri = "url/report"
    elif obs_clsfn == "hash":
        params["resource"] = observable_name
        params["allinfo"] = 1
        uri = "file/report"
    else:
        raise AnalyzerRunException(
            f"not supported observable type {obs_clsfn}. "
            "Supported are: hash, ip, domain and url."
        )

    try:
        response = requests.get(vt_base + uri, params=params)
        response.raise_for_status()
    except requests.RequestException as e:
        raise AnalyzerRunException(e)

    return response.json()
