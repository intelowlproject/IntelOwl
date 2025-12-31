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

        # Select API version
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
            # Base lookup
            response = session.ip(self.observable_name)

            # SAFE, CodeQL-approved merge for v2
            if self.greynoise_api_version == "v2":
                riot_data = session.riot(self.observable_name)
                if isinstance(riot_data, dict):
                    response.update(riot_data)

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
            logger.info("Greynoise lookup returned no results for observable")
            response["not_found"] = True

        return response

    def _do_create_data_model(self):
        return super()._do_create_data_model() and (
            self.report.report.get("riot", False)
            or self.report.report.get("noise", False)
        )

    def _update_data_model(self, data_model):
        from api_app.analyzers_manager.models import AnalyzerReport

        super()._update_data_model(data_model)
        classification = self.report.report.get("classification", None)
        riot = self.report.report.get("riot", None)
        noise = self.report.report.get("noise", None)

        if classification:
            classification = classification.lower()
            self.report: AnalyzerReport

            if classification == self.EVALUATIONS.MALICIOUS.value:
                if not noise:
                    logger.error("Greynoise inconsistency detected: malicious classification without noise flag")
                data_model.evaluation = self.EVALUATIONS.MALICIOUS.value
                data_model.reliability = 7

            elif classification == "unknown":
                if riot:
                    data_model.evaluation = self.EVALUATIONS.TRUSTED.value
                    data_model.reliability = 1
                elif noise:
                    data_model.evaluation = self.EVALUATIONS.MALICIOUS.value

            elif classification == "benign":
                data_model.evaluation = self.EVALUATIONS.TRUSTED.value
                data_model.reliability = 7

            else:
                logger.warning(
                      "Unexpected classification received from Greynoise analyzer"
                )

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(GreyNoise, "ip", return_value={"noise": True}),
                patch.object(GreyNoise, "riot", return_value={"riot": True}),
            )
        ]
        return super()._monkeypatch(patches=patches)
