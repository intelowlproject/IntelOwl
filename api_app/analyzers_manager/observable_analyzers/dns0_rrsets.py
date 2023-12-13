import re
from logging import getLogger
from typing import Dict

import dateparser
import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = getLogger(__name__)

_supported_dns_types = [
    "A",
    1,
    "AAAA",
    28,
    "AFSDB",
    18,
    "APL",
    42,
    "AXFR",
    252,
    "CAA",
    257,
    "CDNSKEY",
    60,
    "CDS",
    59,
    "CERT",
    37,
    "CNAME",
    5,
    "CSYNC",
    62,
    "DHCID",
    49,
    "DLV",
    32769,
    "DNAME",
    39,
    "DNSKEY",
    48,
    "DS",
    43,
    "EUI48",
    108,
    "EUI64",
    109,
    "HINFO",
    13,
    "HIP",
    55,
    "HTTPS",
    65,
    "IPSECKEY",
    45,
    "IXFR",
    251,
    "KEY",
    25,
    "KX",
    36,
    "LOC",
    29,
    "MX",
    15,
    "NAPTR",
    35,
    "NS",
    2,
    "NSEC",
    47,
    "NSEC3",
    50,
    "NSEC3PARAM",
    51,
    "OPENPGPKEY",
    61,
    "OPT",
    41,
    "PTR",
    12,
    "RRSIG",
    46,
    "SIG",
    24,
    "SMIMEA",
    53,
    "SOA",
    6,
    "SRV",
    33,
    "SSHFP",
    44,
    "SVCB",
    64,
    "TA",
    32768,
    "TKEY",
    249,
    "TLSA",
    52,
    "TSIG",
    250,
    "TXT",
    16,
    "URI",
    256,
    "ZONEMD",
    63,
]

_supported_sort_types = [
    "first_seen",
    "last_seen",
]

_supported_format_types = [
    "json",
    "cof",
    "dig",
]

_supported_directions = [
    "right",
    "left",
]

_min_limit_value = 0
_max_limit_value = 50000

_min_offset_value = 0


class DNS0Rrsets(classes.ObservableAnalyzer):
    base_url: str = "https://api.dns0.eu/rrsets"

    _api_key: str
    direction: str
    name: str
    data: str
    type: list[str]
    from_date: str
    to_date: str
    not_before: str
    sort: str
    format: str
    limit: int
    offset: int

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self._validate_params()

    def run(self):
        params = self._create_params()
        headers = self._create_headers()

        response = requests.get(self.base_url, params=params, headers=headers)
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise AnalyzerRunException(e)

        return response.json()

    def _create_headers(self):
        headers = {
            "Accept": "application/json",
        }
        if hasattr(self, "_api_key") and self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _validate_params(self):
        if hasattr(self, "direction") and self.direction not in _supported_directions:
            raise AnalyzerConfigurationException("Matching direction not specified!")

        if hasattr(self, "type") and any(
            dns_types not in _supported_dns_types for dns_types in self.type
        ):
            raise AnalyzerConfigurationException("DNS record not supported!")

        if hasattr(self, "sort") and self.sort not in _supported_sort_types:
            raise AnalyzerConfigurationException(
                f"Sort type {self.sort} not supported! "
                f"Available sort types are: {_supported_sort_types}"
            )

        if hasattr(self, "format") and self.format not in _supported_format_types:
            raise AnalyzerConfigurationException(
                f"Format type {self.format} not supported! "
                f"Available format types are: {_supported_format_types}"
            )

        if (
            hasattr(self, "limit")
            and not _min_limit_value < self.limit <= _max_limit_value
        ):
            raise AnalyzerConfigurationException(
                f"{self.limit} is out of bound! "
                f"Max value is {_max_limit_value}, min value is {_min_limit_value}"
            )

        if hasattr(self, "offset") and self.offset < _min_offset_value:
            raise AnalyzerConfigurationException(
                f"{self.offset} can't be below {_min_offset_value}"
            )

    @staticmethod
    def convert_date_type(date_string):
        if not date_string:
            return False

        date_parsed = (
            DNS0Rrsets.convert_unix_timestamp(date_string)
            or DNS0Rrsets.convert_relative_date(date_string)
            or DNS0Rrsets.convert_date(date_string)
        )
        if not date_parsed:
            raise AnalyzerRunException("Error in date format!")
        return date_parsed

    @staticmethod
    def convert_relative_date(date):
        # accepts string matching the format:
        # - at the beginning
        # a number
        # a character indicating Year, Month or Day
        pattern = re.compile(r"-\d+[YMD]")
        if match := pattern.match(date):
            return match.group()
        return False

    @staticmethod
    def convert_date(date):
        pattern = re.compile(r"^(\d{4}-\d{2}-\d{2})$")
        if match := pattern.match(date):
            return dateparser.parse(match.group())
        return False

    @staticmethod
    def convert_unix_timestamp(timestamp):
        try:
            return str(int(timestamp))
        except Exception:
            return False

    def _create_params(self):
        query_type = None
        if hasattr(self, "direction") and self.direction:
            if self.direction == "left":
                query_type = "name"
            elif self.direction == "right":
                query_type = "data"
        params = {query_type: self.observable_name}

        # pass list of dns types parameter
        if hasattr(self, "type") and self.type:
            # convert the element that are int
            res = [int(elem) if elem.isdigit() else elem for elem in self.type]
            params["type"] = res

        # convert dates to correct format
        if hasattr(self, "from_date") and self.from_date:
            if result := self.convert_date_type(self.from_date):
                params["from"] = result

        if hasattr(self, "to_date") and self.to_date:
            if result := self.convert_date_type(self.to_date):
                params["to"] = result

        if hasattr(self, "not_before") and self.not_before:
            if result := self.convert_date_type(self.not_before):
                params["not_before"] = result

        if hasattr(self, "sort") and self.sort:
            params["sort"] = self.sort

        if hasattr(self, "format") and self.format:
            params["format"] = self.format

        if hasattr(self, "limit") and self.limit:
            params["limit"] = self.limit

        if hasattr(self, "offset") and self.offset:
            params["offset"] = self.offset

        return params

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
