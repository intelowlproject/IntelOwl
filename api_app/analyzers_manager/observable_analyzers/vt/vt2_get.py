# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.constants import ObservableTypes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

vt_base = "https://www.virustotal.com/vtapi/v2/"


class VirusTotalv2(classes.ObservableAnalyzer):
    _api_key_name: str

    def run(self):
        resp = vt_get_report(
            self._api_key_name, self.observable_name, self.observable_classification
        )

        resp_code = resp.get("response_code", 1)
        verbose_msg = resp.get("verbose_msg", "")
        if resp_code == -1 or "Invalid resource" in verbose_msg:
            self.report.errors.append(verbose_msg)
            raise AnalyzerRunException(f"response code {resp_code}. response: {resp}")
        return resp

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)


def vt_get_report(api_key, observable_name, obs_clsfn):
    params = {"apikey": api_key}
    if obs_clsfn == ObservableTypes.DOMAIN:
        params["domain"] = observable_name
        uri = "domain/report"
    elif obs_clsfn == ObservableTypes.IP:
        params["ip"] = observable_name
        uri = "ip-address/report"
    elif obs_clsfn == ObservableTypes.URL:
        params["resource"] = observable_name
        uri = "url/report"
    elif obs_clsfn == ObservableTypes.HASH:
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

    try:
        return_item = response.json()
    except Exception as e:
        raise AnalyzerRunException(
            f"Response is not a JSON!? Response type:{response.text} Error:{e}"
        )

    return return_item
