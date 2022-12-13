# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from ipaddress import AddressValueError, IPv4Address
from typing import List
from urllib.parse import urlparse

import OTXv2

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class OTX(classes.ObservableAnalyzer):
    """This class use an OTX API to download data about an observable.
    Observable's data are divided into sections:
    It's possible to download only some sections to reduce the wait time:
    Download all the data is slow with the IP addresses.
    """

    def set_params(self, params):
        self._api_key = self._secrets["api_key_name"]
        self.verbose = params.get("verbose", False)
        self.sections = params.get("sections", ["general"])
        self.full_analysis = params.get("full_analysis", False)

    def _extract_indicator_type(self) -> "OTXv2.IndicatorTypes":
        observable_classification = self.observable_classification
        if observable_classification == self.ObservableTypes.IP:
            otx_type = OTXv2.IndicatorTypes.IPv4
        elif observable_classification == self.ObservableTypes.URL:
            to_analyze_observable = urlparse(self.observable_name).hostname

            try:
                to_analyze_observable = IPv4Address(to_analyze_observable)
            except AddressValueError:
                otx_type = OTXv2.IndicatorTypes.DOMAIN
            else:
                otx_type = OTXv2.IndicatorTypes.IPv4

            if not to_analyze_observable:
                raise AnalyzerRunException("extracted observable is None")
        elif observable_classification == self.ObservableTypes.DOMAIN:
            otx_type = OTXv2.IndicatorTypes.DOMAIN
        elif observable_classification == self.ObservableTypes.HASH:
            otx_type = OTXv2.IndicatorTypes.FILE_HASH_MD5
        else:
            raise AnalyzerRunException(
                f"not supported observable classification {observable_classification}"
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

    def run(self):
        otx = OTXv2.OTXv2(self._api_key)

        to_analyze_observable = self.observable_name
        otx_type = self._extract_indicator_type()

        if self.full_analysis:
            self.sections = otx_type.sections

        # check if all requested sections are available for the observable type
        not_supported_requested_section_list = list(
            filter(
                lambda requested_section: requested_section not in otx_type.sections,
                self.sections,
            )
        )
        if not_supported_requested_section_list:
            raise AnalyzerRunException(
                f"Sections: {not_supported_requested_section_list} are not supported "
                f"for indicator type: {otx_type}"
            )

        result = {}
        for section in self.sections:
            try:
                details = otx.get_indicator_details_by_section(
                    indicator_type=otx_type,
                    indicator=to_analyze_observable,
                    section=section,
                )
            except (OTXv2.BadRequest, OTXv2.NotFound) as e:
                raise AnalyzerRunException(e)
            else:
                # This mapping is used to avoid a verbose elif structure:
                # Each keyword is mapped in a tuple with the logic to extract the data
                # and the name of the output field
                section_extractor_mapping = {
                    "general": (self._extract_pulses, "pulses"),
                    "geo": (OTX._extract_geo, "geo"),
                    "malware": (OTX._extract_malware_samples, "malware_samples"),
                    "passive_dns": (OTX._extract_passive_dns, "passive_dns"),
                    "reputation": (OTX._extract_reputation, "reputation"),
                    "url_list": (OTX._extract_url_list, "url_list"),
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

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch("requests.Session.get", return_value=MockResponse({}, 200))
            )
        ]
        return super()._monkeypatch(patches=patches)
