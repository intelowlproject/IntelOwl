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

    def update(cls) -> bool:
        pass

    def _validate_params(self):
        super()._validate_params()
        if hasattr(self, "direction") and self.direction not in _supported_directions:
            raise AnalyzerConfigurationException("Matching direction not specified!")

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
