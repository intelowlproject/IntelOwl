# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import requests

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.data_model_manager.enums import DataModelTags

logger = logging.getLogger(__name__)

# The flags that each mean the address hides who is behind it. Tor and relays are
# answered with no key; the VPN and proxy flags with a key on a paid plan.
_ANONYMIZER_FLAGS = (
    "is_tor",
    "is_relay",
    "is_vpn",
    "is_resproxy",
    "is_dcproxy",
    "is_mobproxy",
    "is_pubproxy",
)
# What the address is used for, kept in additional_info when the answer has it.
_OTHER_FLAGS = ("is_hosting", "is_cdn", "is_bot", "is_anycast", "is_carrier", "is_satellite")
# The detection objects whose provider is worth keeping, e.g. "vpn" -> "vpn_provider".
_PROVIDERS = (
    "vpn",
    "relay",
    "resproxy",
    "dcproxy",
    "mobproxy",
    "pubproxy",
    "hosting",
    "carrier",
    "satellite",
)


class InternetData(ObservableAnalyzer):
    """Look up an IP address's location, network, company and abuse contact.

    One request to https://api.internetdata.io/<ip>. With no API key
    (https://internetdata.io/terms#no-key, https://internetdata.io/privacy) it
    answers the country, the ASN and prefix, the company using the address, its
    abuse contact and reverse DNS, and whether it is Tor, a privacy relay,
    anycast, carrier or satellite space; a key on a paid plan adds the city and
    coordinates, the VPN, proxy and hosting flags and their providers.
    """

    url: str = "https://api.internetdata.io/"
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
            raise AnalyzerRunException(f"InternetData answered HTTP {response.status_code}: {message}")

        return result

    def _do_create_data_model(self) -> bool:
        # A private or reserved address has no location or network to report.
        if self.report.report.get("is_bogon"):
            return False
        return super()._do_create_data_model()

    def _update_data_model(self, data_model) -> None:
        super()._update_data_model(data_model)
        report = self.report.report

        # No evaluation: a flag says what the address is, not that it is malicious.
        # is_tor covers every Tor relay, not only exits, so no tor_exit_node tag.
        if any(report.get(flag) for flag in _ANONYMIZER_FLAGS):
            data_model.tags = [DataModelTags.ANONYMIZER.value]

        asn = report.get("asn") or {}
        data_model.asn = asn.get("asn") or None
        data_model.org_name = asn.get("name") or None
        data_model.isp = (report.get("company") or {}).get("name") or None
        data_model.country_code = (report.get("location") or {}).get("country") or None

        info = {
            flag: report[flag] for flag in (*_ANONYMIZER_FLAGS, *_OTHER_FLAGS) if report.get(flag) is not None
        }
        for key in _PROVIDERS:
            provider = (report.get(key) or {}).get("provider_name")
            if provider:
                info[f"{key}_provider"] = provider
        for key, value in (
            ("prefix", asn.get("prefix")),
            ("company_domain", (report.get("company") or {}).get("domain")),
            ("abuse_email", (report.get("abuse") or {}).get("email")),
            ("hostname", report.get("hostname")),
        ):
            if value:
                info[key] = value
        data_model.additional_info = info
