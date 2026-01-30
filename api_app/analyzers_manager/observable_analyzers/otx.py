# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from ipaddress import AddressValueError, IPv4Address
from typing import List
from urllib.parse import urlparse

import OTXv2
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from api_app.helpers import get_hash_type

logger = logging.getLogger(__name__)


class OTXv2Extended(OTXv2.OTXv2):
    """
    This is to add "timeout" feature without having to do a fork
    Once this PR is merged: https://github.com/AlienVault-OTX/OTX-Python-SDK/pull/66
    we can remove this and use the upstream
    """

    def __init__(self, *args, timeout=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.timeout = timeout

    def session(self):
        # modified version where retries are not implemented.
        # this was needed because, otherwise, the analyzer could last too much time
        # and become the bottleneck of all the application
        if self.request_session is None:
            self.request_session = requests.Session()

        return self.request_session

    def get(self, url, **kwargs):
        try:
            response = self.session().get(
                self.create_url(url, **kwargs),
                headers=self.headers,
                proxies=self.proxies,
                verify=self.verify,
                cert=self.cert,
                timeout=self.timeout,
            )
            return self.handle_response_errors(response).json()
        except (
            OTXv2.requests.exceptions.RetryError,
            OTXv2.requests.exceptions.Timeout,
        ) as e:
            raise OTXv2.RetryError(e)


class OTX(classes.ObservableAnalyzer):
    """This class use an OTX API to download data about an observable.
    Observable's data are divided into sections:
    It's possible to download only some sections to reduce the wait time:
    Download all the data is slow with the IP addresses.
    """

    verbose: bool
    sections: list
    full_analysis: bool
    timeout: int = 30

    _api_key_name: str

    def _extract_indicator_type(self) -> "OTXv2.IndicatorTypes":
        observable_classification = self.observable_classification
        if observable_classification == Classification.IP:
            otx_type = OTXv2.IndicatorTypes.IPv4
        elif observable_classification == Classification.URL:
            to_analyze_observable = urlparse(self.observable_name).hostname

            try:
                to_analyze_observable = IPv4Address(to_analyze_observable)
            except AddressValueError:
                otx_type = OTXv2.IndicatorTypes.DOMAIN
            else:
                otx_type = OTXv2.IndicatorTypes.IPv4

            if not to_analyze_observable:
                raise AnalyzerRunException("extracted observable is None")
        elif observable_classification == Classification.DOMAIN:
            otx_type = OTXv2.IndicatorTypes.DOMAIN
        elif observable_classification == Classification.HASH:
            matched_type = get_hash_type(self.observable_name)
            if matched_type == "md5":
                otx_type = OTXv2.IndicatorTypes.FILE_HASH_MD5
            elif matched_type == "sha-1":
                otx_type = OTXv2.IndicatorTypes.FILE_HASH_SHA1
            elif matched_type == "sha-256":
                otx_type = OTXv2.IndicatorTypes.FILE_HASH_SHA256
            else:
                raise AnalyzerRunException(f"hash {matched_type} not supported")
        else:
            raise AnalyzerRunException(f"not supported observable classification {observable_classification}")
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
    def _extract_malware_samples(cls, malware_data: dict) -> List[dict]:
        return [
            {"hash": sample.get("hash", ""), "detections": sample.get("detections", {})}
            for sample in malware_data.get("data", [])
        ]

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
        otx = OTXv2Extended(timeout=self.timeout, api_key=self._api_key_name, user_agent="IntelOwl")

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
            logger.warning(
                f"Sections: {not_supported_requested_section_list}"
                f" are not supported for indicator type: {otx_type}. "
                "We remove them from the search."
            )
            for not_supported in not_supported_requested_section_list:
                self.sections.remove(not_supported)

        result = {}
        for section in self.sections:
            logger.info(f"requesting OTX info for indicator {to_analyze_observable} and section {section}")
            try:
                details = otx.get_indicator_details_by_section(
                    indicator_type=otx_type,
                    indicator=to_analyze_observable,
                    section=section,
                )
            except (OTXv2.BadRequest, OTXv2.RetryError) as e:
                raise AnalyzerRunException(f"Error while requesting data to OTX: {e}")
            except OTXv2.NotFound as e:
                logger.info(f"{to_analyze_observable} not found: {e}")
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
                logger.debug(
                    f"observable {to_analyze_observable} extracted data: {data}, field name: {field_name}"
                )
                result[field_name] = data
                logger.debug(f"result: {result}")
        return result
