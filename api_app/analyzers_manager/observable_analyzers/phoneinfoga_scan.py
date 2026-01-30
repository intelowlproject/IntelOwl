import logging
from enum import Enum
from typing import Dict, List

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerConfigurationException

logger = logging.getLogger(__name__)


class SCANNER_NAMES(Enum):
    LOCAL = "local"
    NUM_VERIFY = "numverify"
    GOOGLECSE = "googlecse"
    OVH = "ovh"

    @classmethod
    def values(cls):
        return list(map(lambda c: c.value, cls))


class Phoneinfoga(classes.ObservableAnalyzer, classes.DockerBasedAnalyzer):
    """
    Docker based analyzer for phoneinfoga
    """

    def update(self) -> bool:
        pass

    observable_name: str
    scanners: List[str]
    all_scanners: bool = True
    googlecse_max_results: int = 10
    name: str = "phoneinfoga"
    # here is a list of pre declared api keys, user can put
    # values as per their required scanner, by default it is null

    _NUMVERIFY_API_KEY: str = ""
    _GOOGLECSE_CX: str = ""
    _GOOGLE_API_KEY: str = ""

    url = "http://phoneinfoga:5000"

    def config(self, runtime_configuration: Dict):
        super().config(runtime_configuration)
        if self.all_scanners:
            self.scanners = SCANNER_NAMES.values()
        else:
            for scanner in self.scanners:
                if scanner not in SCANNER_NAMES.values():
                    raise AnalyzerConfigurationException(
                        f"Scanner {scanner} not supported. Choices are {', '.join(SCANNER_NAMES.values())}"
                    )

    def run(self):
        result = {}
        for scanner in self.scanners:
            try:
                url: str = f"{self.url}/api/v2/scanners/{scanner}/run"
                options = {}
                if scanner == SCANNER_NAMES.NUM_VERIFY.value:
                    options["NUMVERIFY_API_KEY"] = self._NUMVERIFY_API_KEY
                elif scanner == SCANNER_NAMES.GOOGLECSE.value:
                    options = {
                        "GOOGLECSE_CX": self._GOOGLECSE_CX,
                        "GOOGLE_API_KEY": self._GOOGLE_API_KEY,
                        "GOOGLECSE_MAX_RESULTS": self.googlecse_max_results,
                    }
                response = requests.post(
                    url,
                    headers={
                        "Content-Type": "application/json",
                        "accept": "application/json",
                    },
                    json={"number": self.observable_name, "options": options},
                )
                response.raise_for_status()
                result[scanner] = response.json()
            except requests.RequestException as e:
                if scanner == "ovh":
                    logger.info(f"ovh scanner seems not working. {e}", stack_info=True)
                else:
                    logger.error(e, stack_info=True)
                self.report.errors.append(str(e))

        return result
