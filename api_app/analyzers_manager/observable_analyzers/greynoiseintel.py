# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from greynoise import GreyNoise

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch


class MockGreyNoise:
    def __init__(self, *args, **kwargs):
        pass

    def ip(self, *args, **kwargs):
        return {"noise": True}

    def riot(self, *args, **kwargs):
        return {"riot": True}


class GreyNoiseAnalyzer(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.api_version = params.get("greynoise_api_version", "v3")
        self.max_records_to_retrieve = int(params.get("max_records_to_retrieve", 500))

    def run(self):
        if self.api_version == "v2":
            try:
                api_key = self._secrets["api_key_name"]
                session = GreyNoise(
                    api_key=api_key, integration_name="greynoise-intelowl-v1.0"
                )
                response = session.ip(self.observable_name)
                response |= session.riot(self.observable_name)
            except Exception as e:
                raise AnalyzerRunException(f"GreyNoise Exception: {e}")
        elif self.api_version == "v3":
            try:
                api_key = self._secrets["api_key_name"]
                params = {
                    "integration_name": "greynoise-community-intelowl-v1.0",
                    "offering": "Community",
                }
                if api_key:
                    params["api_key"] = api_key
                session = GreyNoise(**params)
                response = session.ip(self.observable_name)
            except Exception as e:
                raise AnalyzerRunException(f"GreyNoise Exception: {e}")
        else:
            raise AnalyzerRunException(
                "Invalid API Version. " "Supported are: v2 (paid), v3 (community)"
            )

        return response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "greynoise.GreyNoise",
                    return_value=MockGreyNoise(),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
