# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer


class NucleiAnalyzer(ObservableAnalyzer, DockerBasedAnalyzer):
    url: str = "http://nuclei_analyzer:4008/run-nuclei"
    template_dirs: list
    max_tries: int = 10
    poll_distance: int = 10

    def run(self):
        """
        Prepares and executes a Nuclei scan through the Docker-based API.
        """
        # Prepare request data
        self.template_dirs = ["dns"]
        print("hello")
        req_data = {
            "url": self.observable_name,  # The URL or observable to scan
            "template_dirs": self.template_dirs
            or [],  # Use provided template directories or default to an empty list
        }

        # Execute the request
        report = self._docker_run(req_data=req_data, req_files=None)
        print("helllo")

        print(report)
        return report
