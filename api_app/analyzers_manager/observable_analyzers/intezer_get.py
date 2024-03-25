# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from datetime import timedelta
from typing import Dict

import intezer_sdk.consts
from intezer_sdk import api as intezer_api
from intezer_sdk import errors as intezer_errors
from intezer_sdk.analysis import FileAnalysis

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch


class IntezerGet(ObservableAnalyzer):
    soft_time_limit: int
    _api_key_name: str

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        self.timeout = self.soft_time_limit - 5
        # interval
        self.poll_interval = 3
        # read secret and set API key
        intezer_api.set_global_api(api_key=self._api_key_name)
        intezer_sdk.consts.USER_AGENT = "IntelOwl"

    def run(self):
        result = {}
        try:
            # run analysis
            analysis = FileAnalysis(file_hash=self.observable_name)
            analysis.send(wait=False)
            analysis.wait_for_completion(
                interval=self.poll_interval,
                sleep_before_first_check=True,
                timeout=timedelta(seconds=self.timeout),
            )
        except (intezer_errors.HashDoesNotExistError, intezer_errors.InsufficientQuota):
            result.update(hash_found=False)
        except intezer_errors.IntezerError as e:
            raise AnalyzerRunException(e)
        except TimeoutError as e:
            raise e
        else:
            result.update(analysis.result(), hash_found=True)

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(FileAnalysis, "send", return_value=None),
                patch.object(FileAnalysis, "wait_for_completion", return_value=None),
                patch.object(FileAnalysis, "result", return_value={"test": "test"}),
            )
        ]
        return super()._monkeypatch(patches=patches)
