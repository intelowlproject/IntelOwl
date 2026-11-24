# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.data_model_manager.enums import DataModelTags

logger = logging.getLogger(__name__)

# The flags that each mean the address hides who is behind it. The proxy flags
# (residential, datacenter, mobile, public) are answered with a paid key only.
_ANONYMIZER_FLAGS = ("is_vpn", "is_relay", "is_resproxy", "is_dcproxy", "is_mobproxy", "is_pubproxy")


class VPNDetection(ObservableAnalyzer):
    """Check whether an IP address is a VPN, a Tor node or a privacy relay.

    One request to https://api.vpndetection.io/<ip>. It needs no API key
    (https://vpndetection.io/terms#no-key, https://vpndetection.io/privacy); a key
    adds the residential, datacenter, mobile and public proxy flags and the VPN's
    provider on a paid plan.
    """

    url: str = "https://api.vpndetection.io/"
    _api_key_name: str = ""

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        headers = {"User-Agent": "IntelOwl"}
        if self._api_key_name:
            headers["Authorization"] = f"Bearer {self._api_key_name}"
        try:
            response = requests.get(self.url + self.observable_name, headers=headers, timeout=30)
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        try:
            result = response.json()
        except ValueError:
            result = None

        if response.status_code != 200 or not isinstance(result, dict):
            message = result.get("error") if isinstance(result, dict) else response.text[:200]
            raise AnalyzerRunException(f"VPNDetection answered HTTP {response.status_code}: {message}")

        return result

    def _do_create_data_model(self) -> bool:
        # Only a flag is an opinion: an address with none set is not a statement
        # that it is safe, so it creates no data model.
        report = self.report.report
        if not report.get("is_tor") and not any(report.get(flag) for flag in _ANONYMIZER_FLAGS):
            return False
        return super()._do_create_data_model()

    def _update_data_model(self, data_model) -> None:
        super()._update_data_model(data_model)
        report = self.report.report

        # is_tor covers every Tor relay, not only exits, so no tor_exit_node tag.
        data_model.tags = [DataModelTags.ANONYMIZER.value]

        asn = report.get("asn") or {}
        data_model.asn = asn.get("asn")
        data_model.org_name = asn.get("name")
        data_model.country_code = (report.get("location") or {}).get("country")
        flags = ("is_tor", *_ANONYMIZER_FLAGS)
        data_model.additional_info = {flag: report[flag] for flag in flags if report.get(flag) is not None}
        provider = (report.get("vpn") or {}).get("provider_name")
        if provider:
            data_model.additional_info["vpn_provider"] = provider
