# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json
from typing import Dict, Optional
from urllib.parse import urlparse

import dateparser
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from api_app.choices import Classification
from certego_saas.apps.user.models import User

_query_types = [
    "domain",
    "rrname-wildcard-left",
    "rrname-wildcard-right",
    "names",
    "rdata-wildcard-left",
    "rdata-wildcard-right",
]
# empty means all rrtypes
# ANY-DNSSEC is an API-specific rrtype that represent all DNSSEC rrtypes
_supported_rrtype = [
    "",
    "A",
    "AAAA",
    "ALIAS",
    "CNAME",
    "MX",
    "NS",
    "PTR",
    "SOA",
    "SRV",
    "TXT",
    "ANY-DNSSEC",
]
_supported_api_version = [1, 2]


class DNSdb(classes.ObservableAnalyzer):
    """Farsight passive DNS API

    Support different server.
    Support version 1 and 2.
    Allow filter on rrtype, count value and timestamp on time fields.
    Allow different query types: normal, with left or right wildcard and nameserver.
    """

    _api_key_name: str
    server: str
    api_version: int
    rrtype: str
    query_type: str
    limit: int
    time: dict

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        # API settings
        self._time_first_before = self.time.get("first_before", "")
        self._time_first_after = self.time.get("first_after", "")
        self._time_last_before = self.time.get("last_before", "")
        self._time_last_after = self.time.get("last_after", "")
        self.no_results_found = False

    def run(self):
        # validate params
        self._validate_params()

        # generate request parts
        headers = self._create_headers()
        url = self._create_url()
        params = self._create_params()

        # perform request
        response = requests.get(url, params=params, headers=headers)
        # for API v1, 404 means no results found
        if self.api_version == 1 and response.status_code == 404:
            self.no_results_found = True
        else:
            response.raise_for_status()

        # validate output
        return self._parse_result(response.text)

    def _validate_params(self):
        """Raise an AnalyzerRunException if some params are not valid"""

        if self.api_version not in _supported_api_version:
            raise AnalyzerRunException(
                f"{self.api_version} not supported version,available versions: {_supported_api_version}"
            )

        if str(self.rrtype) not in _supported_rrtype:
            raise AnalyzerRunException(f"{self.rrtype} is not a valid rrtype: {_supported_rrtype}")

        if self.query_type and self.query_type not in _query_types:
            raise AnalyzerRunException(f"{self.query_type} not in available query types")

        if not isinstance(self.limit, int):
            raise AnalyzerRunException(f"limit: {self.limit} ({type(self.limit)}) must be a integer")

    @staticmethod
    def convert_date_type(date_string):
        """Convert date into timestamp

        :param date_string: date to be converted into timestamp
        :type date_string: str
        :return: date timestamp
        :rtype: int
        """
        try:
            return int(dateparser.parse(date_string).timestamp())
        except ValueError:
            error_message = f"{date_string} cannot be converted to a valid datetime"
        except TypeError:
            error_message = f"{type(date_string)} is not a string and cannot be converted to a datetime "
        except Exception:
            error_message = (
                f"{date_string} with type: {type(date_string)},"
                f"something wrong happened during conversion to datetime"
            )

        raise AnalyzerRunException(error_message)

    def _create_headers(self):
        """Generate headers for the API request

        :return: headers
        :rtype: dict
        """
        if self.api_version == 1:
            header_application_type = "application/json"
        elif self.api_version == 2:
            header_application_type = "application/x-ndjson"
        else:
            raise AnalyzerRunException(
                f"{self.api_version} not in supported versions list: {_supported_api_version}"
            )

        return {"Accept": header_application_type, "X-API-Key": self._api_key_name}

    def _get_version_endpoint(self, api_version: int):
        if api_version == 1:
            return ""
        elif api_version == 2:
            return "/dnsdb/v2"
        else:
            raise AnalyzerRunException(
                f"{api_version} not in supported versions list: {_supported_api_version}"
            )

    def _create_url(self):
        """Generate API url

        :return: API url
        :rtype: str
        """
        api_version = self._get_version_endpoint(self.api_version)
        observable_to_check = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == Classification.URL:
            observable_to_check = urlparse(self.observable_name).hostname

        if self.observable_classification == Classification.IP:
            endpoint = "rdata/ip"
        elif self.observable_classification in [
            Classification.DOMAIN,
            Classification.URL,
        ]:
            if self.query_type == "domain":
                endpoint = "rrset/name"
            elif self.query_type == "rrname-wildcard-left":
                endpoint = "rrset/name"
                observable_to_check = "*." + observable_to_check
            elif self.query_type == "rrname-wildcard-right":
                endpoint = "rrset/name"
                observable_to_check += ".*"
            elif self.query_type == "names":
                endpoint = "rdata/name"
            elif self.query_type == "rdata-wildcard-left":
                endpoint = "rdata/name"
                observable_to_check = "*." + observable_to_check
            elif self.query_type == "rdata-wildcard-right":
                endpoint = "rdata/name"
                observable_to_check += ".*"
            else:
                raise AnalyzerRunException(f"{self.query_type} not supported")
        else:
            raise AnalyzerRunException(f"{self.observable_classification} not supported")

        return f"https://{self.server}{api_version}/lookup/{endpoint}/{observable_to_check}/{self.rrtype}"

    def _create_params(self):
        """Generate API request params.
        There are filters on time fields and results number.

        :return params: data filters
        :rtype params: dict
        """
        time_first_before = None
        if self._time_first_before:
            time_first_before = self.convert_date_type(self._time_first_before)

        time_first_after = None
        if self._time_first_after:
            time_first_after = self.convert_date_type(self._time_first_after)

        time_last_before = None
        if self._time_last_before:
            time_last_before = self.convert_date_type(self._time_last_before)

        time_last_after = None
        if self._time_last_after:
            time_last_after = self.convert_date_type(self._time_last_after)

        params = {"limit": self.limit}
        if time_first_before:
            params["time_first_before"] = time_first_before
        if time_first_after:
            params["time_first_after"] = time_first_after
        if time_last_before:
            params["time_last_before"] = time_last_before
        if time_last_after:
            params["time_last_after"] = time_last_after

        return params

    def _parse_result(self, result_text):
        """Extract data from Farsight response and create a dict with same fields.
        Different API version have different format, create same dict structure from
        different responses.

        :param result_text: response from Farsight API
        :type result_text: str
        :return json_extracted_results: Data received from Farsight
        :rtype json_extracted_results: dict
        """
        # different versions have different parsers
        json_extracted_results = {"query_successful": "", "data": []}
        if self.api_version == 2:
            # first elem is a context line, last two are a context line and a empty line
            for item in result_text.split("\n"):
                if item:
                    new_element = json.loads(item)
                    # if there is a response element it is wrapped in "obj" field
                    if new_element.get("obj", {}):
                        e = new_element["obj"]
                        json_extracted_results["data"].append(e)
                    # elements are ordered, the begin set the flag to false,
                    # but if the last element is succeeded and set it to true
                    json_extracted_results["query_successful"] = new_element.get("cond", "")
        elif self.api_version == 1:
            json_extracted_results["query_successful"] = "not supported for v1"
            if not self.no_results_found:
                for item in result_text.split("\n"):
                    if item:
                        # in case of no results or error
                        if "Error" not in item:
                            json_extracted_results["data"].append(json.loads(item))
        else:
            raise AnalyzerRunException(
                f"{self.api_version} not supported version, available versions: {_supported_api_version}"
            )

        return json_extracted_results

    def _get_health_check_url(self, user: User = None) -> Optional[str]:
        params = self._config.parameters.annotate_configured(self._config, user).annotate_value_for_user(
            self._config, user
        )
        server = params.get(name="server")
        api_version = self._get_version_endpoint(params.get(name="api_version").value)

        return f"https://{server}{api_version}"
