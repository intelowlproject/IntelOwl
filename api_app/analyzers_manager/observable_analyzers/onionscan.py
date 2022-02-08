# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer


class Onionscan(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Onionscan"
    url: str = "http://tor_analyzers:4001/onionscan"
    # http request polling max number of tries
    max_tries: int = 60
    # interval between http request polling (in seconds)
    poll_distance: int = 10
    verbose = True
    tor_proxy_address = None

    def set_params(self, params):
        self.verbose = params.get("verbose", True)
        self.tor_proxy_address = params.get("torProxyAddress", None)

    def run(self):
        # make request params
        args = []
        if self.verbose:
            args.append("-verbose")
        if self.tor_proxy_address:
            args.extend(["-torProxyAddress", self.tor_proxy_address])
        # make request data
        args.extend(["-jsonReport", self.observable_name])

        req_data = {
            "args": args,
        }

        return self._docker_run(req_data=req_data, req_files=None)
