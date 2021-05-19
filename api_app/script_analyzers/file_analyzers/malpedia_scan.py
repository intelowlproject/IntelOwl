# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import requests

from api_app.exceptions import AnalyzerRunException, AnalyzerConfigurationException
from api_app.script_analyzers.classes import FileAnalyzer
from api_app.helpers import get_binary
from intel_owl import secrets


class MalpediaScan(FileAnalyzer):
    base_url: str = "https://malpedia.caad.fkie.fraunhofer.de/api/"

    def set_config(self, additional_config_params):
        self.api_key_name = additional_config_params.get("api_key_name", "MALPEDIA_KEY")
        self.__api_key = secrets.get_secret(self.api_key_name)

    def run(self):
        if not self.__api_key:
            raise AnalyzerConfigurationException(
                f"No API key retrieved with name: {self.api_key_name}."
            )
        return self._scan_binary()

    def _scan_binary(self):
        """scan a binary against all YARA rules in Malpedia"""

        url = self.base_url + "scan/binary"
        headers = {"Authorization": f"APIToken {self.__api_key}"}
        binary = get_binary(self.job_id)
        files = {"file": binary}

        try:
            response = requests.post(url, headers=headers, files=files)
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(e)

        result = response.json()
        return result
