from logging import getLogger
from typing import Dict

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (
    AnalyzerConfigurationException,
    AnalyzerRunException,
)
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.analyzers_manager.observable_analyzers.dns0.dns0_base import DNS0Mixin
from api_app.models import Parameter, PluginConfig
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
    include_subdomain: bool

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

    def update(self) -> bool:
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

        query = self.observable_name
        if hasattr(self, "include_subdomain") and self.include_subdomain:
            query = "." + query
        params[query_type] = query

        # pass list of dns types parameter
        if hasattr(self, "type") and self.type:
            # convert the element that are int
            res = [int(elem) if elem.isdigit() else elem for elem in self.type]
            params["type"] = res

        return params

    @classmethod
    def _monkeypatch(cls):
        for config in ["DNS0_rrsets_data", "DNS0_rrsets_name"]:
            ac = AnalyzerConfig.objects.get(name=config)
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="from", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value="-1M",
            )
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="to", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value="",
            )
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="not_before", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value="",
            )
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="sort", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value="first_seen",
            )
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="format", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value="json",
            )
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="limit", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value=100,
            )
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="offset", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value=0,
            )
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="type", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value=[],
            )
            PluginConfig.objects.get_or_create(
                analyzer_config=ac,
                parameter=Parameter.objects.get(
                    name="include_subdomain", python_module__pk=ac.python_module_id
                ),
                for_organization=False,
                owner=None,
                value=False,
            )

        ac = AnalyzerConfig.objects.get(name="DNS0_rrsets_name")
        PluginConfig.objects.get_or_create(
            analyzer_config=ac,
            parameter=Parameter.objects.get(
                name="direction", python_module__pk=ac.python_module_id
            ),
            for_organization=False,
            owner=None,
            value="left",
        )

        ac = AnalyzerConfig.objects.get(name="DNS0_rrsets_data")
        PluginConfig.objects.get_or_create(
            analyzer_config=ac,
            parameter=Parameter.objects.get(
                name="direction", python_module__pk=ac.python_module_id
            ),
            for_organization=False,
            owner=None,
            value="right",
        )

        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "data": [
                                {
                                    "first_seen": "2023-04-15T16:50:52.000Z",
                                    "last_seen": "2023-12-14T00:23:52.000Z",
                                    "name": "example.com.",
                                    "type": "A",
                                    "data": ["93.184.216.34"],
                                }
                            ],
                            "meta": {"results": 6},
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
