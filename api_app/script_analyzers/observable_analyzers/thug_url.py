import secrets

from api_app.script_analyzers.classes import ObservableAnalyzer, DockerBasedAnalyzer


class ThugUrl(ObservableAnalyzer, DockerBasedAnalyzer):
    name: str = "Thug"
    url: str = "http://thug:4001/thug"
    # http request polling max number of tries
    max_tries: int = 15
    # interval between http request polling (in seconds)
    poll_distance: int = 30

    def set_config(self, additional_config_params):
        self.args = self._thug_args_builder(additional_config_params)
        self.is_test = additional_config_params.get("test", False)

    @staticmethod
    def _thug_args_builder(config_params):
        user_agent = config_params.get("user_agent", "winxpie60")
        dom_events = config_params.get("dom_events", None)
        use_proxy = config_params.get("use_proxy", False)
        proxy = config_params.get("proxy", None)
        enable_awis = config_params.get("enable_awis", False)
        enable_img_proc = config_params.get("enable_image_processing_analysis", False)
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
        # construct a valid directory name into which thug will save the result
        tmp_dir = secrets.token_hex(4)
        # make request data
        self.args.extend(["-n", "/home/thug/" + tmp_dir, self.observable_name])

        req_data = {
            "args": self.args,
            "callback_context": {"read_result_from": tmp_dir},
        }

        return self._docker_run(req_data=req_data, req_files=None)
