# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, ObservableAnalyzer

logger = logging.getLogger(__name__)


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
                warning = f"Skipping invalid template directory: {template_dir} for observable {self.observable_name}"
                logger.warning(warning)
                self.report.errors.append(warning)
        req_data = {"args": args}

        # Execute the request
        response = self._docker_run(req_data=req_data, req_files=None)

        analysis = response.get("data", [])

        return analysis
