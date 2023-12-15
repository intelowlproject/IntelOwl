from logging import getLogger
from typing import Dict
from urllib.parse import urlparse

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

_supported_fuzzy_params = [
    "swap",
    "omit",
    "repeat",
    "add",
    "typo",
    "bitflip",
    "hyphen",
    "fatfinger",
    "subdomain",
    "vowels",
    "homoglyph",
    "all",
]

_supported_format_types = [
    "json",
    "dig",
]


class DNS0Names(classes.ObservableAnalyzer, DNS0Mixin):
    endpoint: str = "names"

    root: bool
    fuzzy: list[str]

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
        if hasattr(self, "fuzzy") and any(
            fuzzy_params not in _supported_fuzzy_params for fuzzy_params in self.fuzzy
        ):
            raise AnalyzerConfigurationException(
                "Fuzzy type not supported! "
                "The list of supported fuzzy is at: "
                "https://docs.dns0.eu/dns-api/names#fuzziness"
            )

        if hasattr(self, "format") and self.format not in _supported_format_types:
            raise AnalyzerConfigurationException(
                f"Format type {self.format} not supported! "
                f"Available format types are: {_supported_format_types}"
            )

    def _create_params(self):
        params = super()._create_params()
        target_observable = self.observable_name
        if self.observable_classification == self.ObservableTypes.URL:
            target_observable = urlparse(self.observable_name).hostname
        params["q"] = target_observable

        # convert root parameter into 1 or 0
        if hasattr(self, "root") and self.root:
            params["root"] = int(self.root)

        # pass list of fuzzy parameter
        if hasattr(self, "fuzzy") and self.fuzzy:
            params["fuzzy"] = self.fuzzy

        return params

    @classmethod
    def _monkeypatch(cls):
        ac = AnalyzerConfig.objects.get(name="DNS0_rrsets_name")
        PluginConfig.objects.create(
            analyzer_config=ac.pk,
            parameter=Parameter.objects.get(
                name="limit", python_module__pk=ac.python_module_id
            ),
            for_organization=False,
            owner=None,
            value=100,
        )
        PluginConfig.objects.create(
            analyzer_config=ac.pk,
            parameter=Parameter.objects.get(
                name="from", python_module__pk=ac.python_module_id
            ),
            for_organization=False,
            owner=None,
            value="-1M",
        )

        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "data": [
                                {
                                    "first_seen": "2023-12-14T16:37:44.000Z",
                                    "last_seen": "2023-12-14T16:37:44.000Z",
                                    "name": "gcfr2.example.opentlc.com.",
                                }
                            ],
                            "meta": {"results": 834824},
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
