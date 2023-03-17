# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import secrets

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer


class ThugUrl(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Thug"
    url: str = "http://malware_tools_analyzers:4002/thug"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in seconds)
    poll_distance: int = 30

    user_agent: str
    dom_events: str
    use_proxy: bool
    proxy: str
    enable_awis: bool
    enable_image_processing_analysis: bool

    def _thug_args_builder(self):
        user_agent = self.user_agent
        dom_events = self.dom_events
        use_proxy = self.use_proxy
        proxy = self.proxy
        enable_awis = self.enable_awis
        enable_img_proc = self.enable_image_processing_analysis
        # make request arguments
        # analysis timeout is set to 5 minutes
        args = ["-T", "300", "-u", str(user_agent)]
        if dom_events:
            args.extend(["-e", str(dom_events)])
        if use_proxy and proxy:
            args.extend(["-p", str(proxy)])
        if enable_awis:
            args.append("--awis")
        if enable_img_proc:
            args.append("--image-processing")

        return args

    def run(self):
        args = self._thug_args_builder()
        # construct a valid directory name into which thug will save the result
        tmp_dir = secrets.token_hex(4)
        # make request data
        args.extend(["-n", "/home/thug/" + tmp_dir, self.observable_name])

        req_data = {
            "args": args,
            "callback_context": {"read_result_from": tmp_dir},
        }

        return self._docker_run(req_data=req_data, req_files=None)
