# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from greynoise import GreyNoise
from greynoise.exceptions import NotFound, RateLimitError, RequestFailure

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class GreyNoiseAnalyzer(classes.ObservableAnalyzer):
    greynoise_api_version: str
    max_records_to_retrieve: int

    _api_key_name: str = None

    @classmethod
    def update(cls) -> bool:
        pass

    @property
    def integration_name(self):
        if self.greynoise_api_version == "v2":
            return "greynoise-intelowl-v1.0"
        elif self.greynoise_api_version == "v3":
            return "greynoise-community-intelowl-v1.0"
        raise RuntimeError(f"Version {self.greynoise_api_version} not configured")

    def run(self):
        response = {}
        if self.greynoise_api_version == "v2":
            session = GreyNoise(
                api_key=self._api_key_name,
                integration_name=self.integration_name,
            )
        elif self.greynoise_api_version == "v3":
            session = GreyNoise(
                api_key=self._api_key_name,
                integration_name=self.integration_name,
                offering="Community",
            )
        else:
            raise AnalyzerRunException(
                "Invalid API Version. Supported are: v2 (paid), v3 (community)"
            )
        try:
            response = session.ip(self.observable_name)
            if self.greynoise_api_version == "v2":
                response |= session.riot(self.observable_name)
        # greynoise library does provide empty messages in case of these errors...
        # so it's better to catch them and create custom management
        except RateLimitError as e:
            self.disable_for_rate_limit()
            self.report.errors.append(e)
            self.report.save()
            raise AnalyzerRunException(f"Rate limit error: {e}")
        except RequestFailure as e:
            self.report.errors.append(e)
            self.report.save()
            raise AnalyzerRunException(f"Request failure error: {e}")
        except NotFound as e:
            logger.info(f"not found error for {self.observable_name} :{e}")
            response["not_found"] = True

        return response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(GreyNoise, "ip", return_value={"noise": True}),
                patch.object(GreyNoise, "riot", return_value={"riot": True}),
            )
        ]
        return super()._monkeypatch(patches=patches)
