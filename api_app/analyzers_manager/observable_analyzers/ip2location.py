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
                api_key = (getattr(self, "_api_key_name", None) or "").strip()
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
        report = _as_dict(getattr(self.report, "report", None))
        proxy = _as_dict(report.get("proxy"))

        asn = _parse_asn(report.get("asn"))
        if asn is not None:
            data_model.asn = asn

        data_model.tags = _merge_tags(data_model.tags, report, proxy)
        data_model.additional_info = _merge_additional_info(data_model.additional_info, report, proxy)


def _as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _is_anonymizer(report: dict, proxy: dict) -> bool:
    if report.get("is_proxy") is True:
        return True
    return any(proxy.get(flag) is True for flag in _ANONYMIZER_FLAGS)


def _merge_tags(existing_tags, report: dict, proxy: dict) -> list:
    tags = list(existing_tags) if existing_tags else []
    candidates = (
        (_is_anonymizer(report, proxy), DataModelTags.ANONYMIZER.value),
        (proxy.get("is_tor") is True, DataModelTags.TOR_EXIT_NODE.value),
        (proxy.get("is_scanner") is True, DataModelTags.SCANNER.value),
    )
    for condition, tag in candidates:
        if condition and tag not in tags:
            tags.append(tag)
    return tags


def _merge_additional_info(existing_info, report: dict, proxy: dict) -> dict:
    info = dict(existing_info) if existing_info else {}
    if "is_proxy" in report:
        info["is_proxy"] = report["is_proxy"]
    if proxy:
        info["proxy"] = proxy
    return info


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
