# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.data_model_manager.enums import DataModelTags

# Proxy object flags that mean the address is an anonymizer. is_data_center is
# not included: a hosting provider is not, by itself, an anonymizer.
_ANONYMIZER_FLAGS = (
    "is_vpn",
    "is_tor",
    "is_public_proxy",
    "is_web_proxy",
    "is_residential_proxy",
    "is_consumer_privacy_network",
)


class Ip2location(classes.ObservableAnalyzer):
    """IP2Location.io IP lookup.

    Two free versions of the service:
    1. keyless: no API key, 1,000 queries per day.
    2. keyed: an API key. A free key allows 50,000 queries per month.

    Free and keyless responses include basic geolocation, ASN, and a boolean
    is_proxy flag. Detailed proxy fields (proxy_type, is_vpn, is_tor,
    is_data_center, is_residential_proxy, provider, and the rest of the proxy
    object) require the IP2Location.io Security plan.
    https://www.ip2location.io/ip2location-documentation
    """

    url: str = "https://api.ip2location.io/"
    api_version: str = "keyless"

    @classmethod
    def update(cls) -> bool:
        pass

    def get_response(self, payload):
        return requests.get(self.url, params=payload, timeout=30)

    def run(self):
        try:
            payload = {"ip": self.observable_name}
            # keyless works without a key. Only the keyed version sends one.
            if self.api_version == "keyed":
                api_key = getattr(self, "_api_key_name", None)
                if not api_key:
                    raise AnalyzerConfigurationException(
                        "Ip2location api_version is keyed but api_key_name is not configured"
                    )
                payload["key"] = api_key

            location_info = self.get_response(payload)
            location_info.raise_for_status()

        except requests.RequestException as exc:
            raise AnalyzerRunException(exc) from exc

        return location_info.json()

    def _update_data_model(self, data_model) -> None:
        super()._update_data_model(data_model)
        report = self.report.report if isinstance(getattr(self.report, "report", None), dict) else {}
        proxy = report.get("proxy") if isinstance(report.get("proxy"), dict) else {}

        asn = _parse_asn(report.get("asn"))
        if asn is not None:
            data_model.asn = asn

        tags = list(data_model.tags or [])
        anonymizer = report.get("is_proxy") is True or any(
            proxy.get(flag) is True for flag in _ANONYMIZER_FLAGS
        )
        if anonymizer and DataModelTags.ANONYMIZER.value not in tags:
            tags.append(DataModelTags.ANONYMIZER.value)
        if proxy.get("is_tor") is True and DataModelTags.TOR_EXIT_NODE.value not in tags:
            tags.append(DataModelTags.TOR_EXIT_NODE.value)
        if proxy.get("is_scanner") is True and DataModelTags.SCANNER.value not in tags:
            tags.append(DataModelTags.SCANNER.value)
        data_model.tags = tags

        info = dict(data_model.additional_info or {})
        if "is_proxy" in report:
            info["is_proxy"] = report["is_proxy"]
        if proxy:
            info["proxy"] = proxy
        data_model.additional_info = info


def _parse_asn(value):
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text.upper().startswith("AS"):
        text = text[2:]
    if text.isdigit():
        return int(text)
    return None
