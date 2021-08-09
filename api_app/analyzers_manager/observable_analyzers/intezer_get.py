# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from datetime import timedelta

from intezer_sdk import api as intezer_api, errors as intezer_errors
from intezer_sdk.analysis import Analysis

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.exceptions import AnalyzerRunException

from tests.mock_utils import if_mock_connections, patch


class IntezerGet(ObservableAnalyzer):
    def set_params(self, params):
        # soft time limit
        soft_time_limit = params.get("soft_time_limit", 100)
        self.timeout = soft_time_limit - 5
        # interval
        self.poll_interval = 3
        # read secret and set API key
        intezer_api.set_global_api(api_key=self._secrets["api_key_name"])

    def run(self):
        result = {}

        try:
            # run analysis
            analysis = Analysis(file_hash=self.observable_name)
            analysis.send(wait=False)
            analysis.wait_for_completion(
                interval=self.poll_interval,
                sleep_before_first_check=True,
                timeout=timedelta(seconds=self.timeout),
            )
            result.update(analysis.result(), hash_found=True)
        except intezer_errors.IntezerError as e:
            raise AnalyzerRunException(e)

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(Analysis, "send", return_value=None),
                patch.object(Analysis, "wait_for_completion", return_value=None),
                patch.object(Analysis, "result", return_value={"test": "test"}),
            )
        ]
        return super()._monkeypatch(patches=patches)
