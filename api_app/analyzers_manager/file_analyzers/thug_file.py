# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import secrets
from api_app.helpers import get_binary
from api_app.analyzers_manager.classes import FileAnalyzer, DockerBasedAnalyzer
from ..observable_analyzers.thug_url import ThugUrl

from tests.mock_utils import (
    patch,
    if_mock,
    mocked_docker_analyzer_get,
    mocked_docker_analyzer_post,
)


@if_mock(
    [
        patch(
            "requests.get",
            side_effect=mocked_docker_analyzer_get,
        ),
        patch(
            "requests.post",
            side_effect=mocked_docker_analyzer_post,
        ),
    ]
)
class ThugFile(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Thug"
    url: str = "http://thug:4001/thug"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in secs)
    poll_distance: int = 30

    def set_params(self, params):
        self.args = ThugUrl._thug_args_builder(params)

    def run(self):
        # construct a valid dir name into which thug will save the result
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        tmp_dir = f"{fname}_{secrets.token_hex(4)}"
        # get the file to send
        binary = get_binary(self.job_id)
        # append final arguments,
        # -n -> output directory
        # -l -> the local file to analyze
        self.args.extend(["-n", "/home/thug/" + tmp_dir, "-l", f"@{fname}"])
        # make request parameters
        req_data = {
            "args": self.args,
            "callback_context": {"read_result_from": tmp_dir},
        }
        req_files = {fname: binary}

        return self._docker_run(req_data, req_files)
