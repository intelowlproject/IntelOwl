# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import secrets

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer


class ThugFile(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "Thug"
    url: str = "http://thug:4002/thug"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in secs)
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
        # construct a valid dir name into which thug will save the result
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        tmp_dir = f"{fname}_{secrets.token_hex(4)}"
        tmp_dir_full_path = "/opt/deploy/thug" + tmp_dir
        # get the file to send
        binary = self.read_file_bytes()
        # append final arguments,
        # -n -> output directory
        # -l -> the local file to analyze
        args.extend(["-n", tmp_dir_full_path, "-l", f"@{fname}"])
        # make request parameters
        req_data = {
            "args": args,
            "callback_context": {"read_result_from": tmp_dir_full_path},
        }
        req_files = {fname: binary}

        return self._docker_run(req_data, req_files)
