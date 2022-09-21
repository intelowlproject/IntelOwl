# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from ipaddress import AddressValueError, IPv4Address
from urllib.parse import urlparse

import OTXv2
import requests

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch


class OTX(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.__api_key = self._secrets["api_key_name"]
        self.verbose = params.get("verbose", False)

    def run(self):
        otx = OTXv2.OTXv2(self.__api_key)

        obs_clsf = self.observable_classification
        to_analyze_observable = self.observable_name

        if obs_clsf == self.ObservableTypes.IP:
            otx_type = OTXv2.IndicatorTypes.IPv4
        elif obs_clsf == self.ObservableTypes.URL:
            to_analyze_observable = urlparse(self.observable_name).hostname

            try:
                to_analyze_observable = IPv4Address(to_analyze_observable)
            except AddressValueError:
                otx_type = OTXv2.IndicatorTypes.DOMAIN
            else:
                otx_type = OTXv2.IndicatorTypes.IPv4

            if not to_analyze_observable:
                raise AnalyzerRunException("extracted observable is None")
        elif obs_clsf == self.ObservableTypes.DOMAIN:
            otx_type = OTXv2.IndicatorTypes.DOMAIN
        elif obs_clsf == self.ObservableTypes.HASH:
            otx_type = OTXv2.IndicatorTypes.FILE_HASH_MD5
        else:
            raise AnalyzerRunException(
                f"not supported observable classification {obs_clsf}"
            )

        result = {}
        try:
            details = otx.get_indicator_details_full(otx_type, to_analyze_observable)
        except (OTXv2.BadRequest, OTXv2.NotFound) as e:
            result["error"] = str(e)
        else:
            result["pulses"] = (
                details.get("general", {}).get("pulse_info", {}).get("pulses", [])
            )
            # for some observables the output could really be overwhelming
            if not self.verbose and result["pulses"]:
                result["pulses"] = result["pulses"][:20]
            for pulse in result["pulses"]:
                pulse_id = pulse.get("id", "")
                if pulse_id:
                    pulse["link"] = f"https://otx.alienvault.com/pulse/{pulse_id}"
            result["geo"] = details.get("geo", {})
            result["malware_samples"] = [
                d.get("hash", "") for d in details.get("malware", {}).get("data", [])
            ]
            result["passive_dns"] = details.get("passive_dns", {}).get(
                "passive_dns", []
            )
            result["reputation"] = details.get("reputation", {}).get("reputation", None)
            result["url_list"] = details.get("url_list", {}).get("url_list", [])
            result["analysis"] = details.get("analysis", {}).get("analysis", {})
            if not self.verbose:
                if result["analysis"] and "plugins" in result["analysis"]:
                    result["analysis"]["plugins"] = "removed because too long"

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(
                    requests.Session, "get", return_value=MockResponse({}, 200)
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
