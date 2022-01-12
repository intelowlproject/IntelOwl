# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer
from tests.mock_utils import patch


class Onionscan(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Onionscan"
    url: str = "http://tor_analyzers:4004/onionscan"
    # http request polling max number of tries
    max_tries: int = 1000
    # interval between http request polling (in seconds)
    poll_distance: int = 30

    def set_params(self, params):
        self.args = self._onionscan_args_builder(params)

    @staticmethod
    def _onionscan_args_builder(params):
        verbose = params.get("verbose", True)
        tor_proxy_address = params.get("torProxyAddress", None)
        # make request arguments
        args = []
        if verbose:
            args.append("-verbose")
        if tor_proxy_address:
            args.extend(["-torProxyAddress", tor_proxy_address])
        return args

    def run(self):
        # make request data
        self.args.extend(["-jsonReport", self.observable_name])

        req_data = {
            "args": self.args,
        }

        return self._docker_run(req_data=req_data, req_files=None)

    @classmethod
    def _monkeypatch(cls, *_) -> None:
        patches = [
            patch(
                "DockerBasedAnalyzer._docker_run",
                return_value="{}",
            )
        ]
        return super()._monkeypatch(patches=patches)
