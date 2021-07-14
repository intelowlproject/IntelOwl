# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.helpers import get_binary
from api_app.analyzers_manager.classes import FileAnalyzer, DockerBasedAnalyzer

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
class APKiD(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "apk_analyzers"
    url: str = "http://apk_analyzers:4004/apkid"
    # http request polling max number of tries
    max_tries: int = 10
    # interval between http request polling (in secs)
    poll_distance: int = 3

    def run(self):
        # construct a valid filename into which thug will save the result
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        # get the file to send
        binary = get_binary(self.job_id)
        # construct arguments, For example this corresponds to,
        # apkid -j file.apk
        args = [
            "-t",
            "20",
            "-j",
            f"@{fname}",
        ]
        req_data = {
            "args": args,
        }
        req_files = {fname: binary}

        return self._docker_run(req_data, req_files)
