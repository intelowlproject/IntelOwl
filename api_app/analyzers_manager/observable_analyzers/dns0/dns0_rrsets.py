from logging import getLogger
from typing import Dict

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.analyzers_manager.observable_analyzers.dns0.dns0_base import DNS0Mixin
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

_supported_format_types = [
    "json",
    "cof",
    "dig",
]

_supported_directions = [
    "right",
    "left",
]


class DNS0Rrsets(classes.ObservableAnalyzer, DNS0Mixin):
    endpoint: str = "rrsets"

    direction: str
    name: str
    data: str
    type: list[str]

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self._validate_params()

    def run(self):
        params = self._create_params()
        headers = self._create_headers()

        response = requests.get(
            self.base_url + self.endpoint, params=params, headers=headers
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as e:
            raise AnalyzerRunException(e)

        return response.json()

    def _validate_params(self):
        super()._validate_params()
        if hasattr(self, "direction") and self.direction not in _supported_directions:
            raise AnalyzerConfigurationException("Matching direction not specified!")

        if hasattr(self, "type") and any(
            dns_types not in _supported_dns_types for dns_types in self.type
        ):
            raise AnalyzerConfigurationException("DNS record not supported!")

        if hasattr(self, "format") and self.format not in _supported_format_types:
            raise AnalyzerConfigurationException(
                f"Format type {self.format} not supported! "
                f"Available format types are: {_supported_format_types}"
            )

    def _create_params(self):
        params = super()._create_params()
        query_type = None
        if hasattr(self, "direction") and self.direction:
            if self.direction == "left":
                query_type = "name"
            elif self.direction == "right":
                query_type = "data"
        params[query_type] = self.observable_name

        # pass list of dns types parameter
        if hasattr(self, "type") and self.type:
            # convert the element that are int
            res = [int(elem) if elem.isdigit() else elem for elem in self.type]
            params["type"] = res

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
