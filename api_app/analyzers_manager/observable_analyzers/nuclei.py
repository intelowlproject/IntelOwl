# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import json

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer


class NucleiAnalyzer(ObservableAnalyzer, DockerBasedAnalyzer):
    url: str = "http://nuclei_analyzer:4008/run-nuclei"
    template_dirs: list
    max_tries: int = 40
    poll_distance: int = 30

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        """
        Prepares and executes a Nuclei scan through the Docker-based API.
        """
        VALID_TEMPLATE_CATEGORIES = {
            "cloud",
            "code",
            "cves",
            "vulnerabilities",
            "dns",
            "file",
            "headless",
            "helpers",
            "http",
            "javascript",
            "network",
            "passive",
            "profiles",
            "ssl",
            "workflows",
            "exposures",
        }

        args = [self.observable_name]

        # Append valid template directories with the "-t" flag
        for template_dir in self.template_dirs:
            if template_dir in VALID_TEMPLATE_CATEGORIES:
                args.extend(["-t", template_dir])
            else:
                print(f"Skipping invalid template directory: {template_dir}")

        req_data = {"args": args}

        # Execute the request
        response = self._docker_run(req_data=req_data, req_files=None)
        json_objects = []
        for line in response.strip().split("\n"):
            try:
                json_objects.append(json.loads(line))
            except json.JSONDecodeError:
                print(f"Skipping non-JSON line: {line}")

        return json_objects
