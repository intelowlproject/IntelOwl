# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from abc import ABCMeta
from ipaddress import AddressValueError, IPv4Address
from typing import List
from urllib.parse import urlparse

import OTXv2

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class BaseOTX(classes.ObservableAnalyzer, metaclass=ABCMeta):
    """Class with utilities functions for OTX"""

    def set_params(self, params):
        self._api_key = self._secrets["api_key_name"]
        self.verbose = params.get("verbose", False)

    def _extract_indicator_type(self) -> "OTXv2.IndicatorTypes":
        obs_clsf = self.observable_classification
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
        return otx_type

    def _extract_pulses(self, general_data: dict) -> List[dict]:
        pulse_list = general_data.get("pulse_info", {}).get("pulses", [])
        # for some observables the output could really be overwhelming
        if not self.verbose and pulse_list:
            pulse_list = pulse_list[:20]
        for pulse in pulse_list:
            pulse_id = pulse.get("id", "")
            if pulse_id:
                pulse["link"] = f"https://otx.alienvault.com/pulse/{pulse_id}"
        return pulse_list

    @classmethod
    def _extract_geo(cls, geo_data: dict) -> dict:
        return geo_data

    @classmethod
    def _extract_malware_samples(cls, malware_data: dict) -> List[str]:
        return [malware.get("hash", "") for malware in malware_data.get("data", [])]

    @classmethod
    def _extract_passive_dns(cls, passive_dns_data: dict) -> List[dict]:
        return passive_dns_data.get("passive_dns", [])

    @classmethod
    def _extract_reputation(cls, reputation_data: dict):
        return reputation_data.get("reputation", None)

    @classmethod
    def _extract_url_list(cls, url_list_data: dict) -> List[dict]:
        return url_list_data.get("url_list", [])

    def _extract_analysis(self, analysis_data: dict) -> dict:
        analysis_result = analysis_data.get("analysis", {})
        if not self.verbose and analysis_result and "plugins" in analysis_result:
            analysis_result["plugins"] = "removed because too long"
        return analysis_result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch("requests.Session.get", return_value=MockResponse({}, 200))
            )
        ]
        return super()._monkeypatch(patches=patches)


class OTX(BaseOTX):
    """This class use an OTX API to download all data about an observable.
    This could be slow in some cases (IPs)
    """

    def run(self):
        otx = OTXv2.OTXv2(self._api_key)

        to_analyze_observable = self.observable_name
        otx_type = self._extract_indicator_type()

        result = {}
        try:
            details = otx.get_indicator_details_full(otx_type, to_analyze_observable)
        except (OTXv2.BadRequest, OTXv2.NotFound) as e:
            result["error"] = str(e)
        else:
            result["pulses"] = self._extract_pulses(details.get("general", {}))
            result["geo"] = self._extract_geo(details.get("geo", {}))
            result["malware_samples"] = self._extract_malware_samples(
                details.get("malware", {})
            )
            result["passive_dns"] = self._extract_passive_dns(
                details.get("passive_dns", {})
            )
            result["reputation"] = self._extract_reputation(
                details.get("reputation", {})
            )
            result["url_list"] = self._extract_url_list(details.get("url_list", {}))
            result["analysis"] = self._extract_analysis(details.get("analysis", {}))

        return result


class OTXSection(BaseOTX):
    """This class use an OTX API to download only some data about an Observable"""

    def set_params(self, params):
        super().set_params(params)
        self.sections = params.get("sections", ["general"])

    def run(self):
        otx = OTXv2.OTXv2(self._api_key)

        to_analyze_observable = self.observable_name
        otx_type = self._extract_indicator_type()

        result = {}
        for section in self.sections:
            try:
                details = otx.get_indicator_details_by_section(
                    indicator_type=otx_type,
                    indicator=to_analyze_observable,
                    section=section,
                )
            except (OTXv2.BadRequest, OTXv2.NotFound) as e:
                result["error"] = str(e)
            except TypeError:
                result["error"] = (
                    f"Section {section} is not currently supported "
                    f"for indicator type: {otx_type}"
                )
            else:
                # This mapping is used to avoid a verbose elif structure:
                # Each keyword is mapped in a tuple with the logic to extract the data
                # and the name of the output field
                section_extractor_mapping = {
                    "general": (self._extract_pulses, "pulses"),
                    "geo": (OTXSection._extract_geo, "geo"),
                    "malware": (OTXSection._extract_malware_samples, "malware_samples"),
                    "passive_dns": (OTXSection._extract_passive_dns, "passive_dns"),
                    "reputation": (OTXSection._extract_reputation, "reputation"),
                    "url_list": (OTXSection._extract_url_list, "url_list"),
                    "analysis": (self._extract_analysis, "analysis"),
                }
                logger.debug(f"OTX raw data: {details}")
                # get the function and the label related to the section
                selected_section_config = section_extractor_mapping[section]
                data = selected_section_config[0](details)
                field_name = selected_section_config[1]
                logger.debug(f"extracted data: {data}, field name: {field_name}")
                result[field_name] = data
                logger.debug(f"result: {result}")
        return result
