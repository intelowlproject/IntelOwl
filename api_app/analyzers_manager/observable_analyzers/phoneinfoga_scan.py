import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (  # AnalyzerConfigurationException
    AnalyzerRunException,
)
from tests.mock_utils import MockUpResponse

logger = logging.getLogger(__name__)


class Phoneinfoga(classes.ObservableAnalyzer, classes.DockerBasedAnalyzer):
    """
    Docker based analyzer for phoneinfoga
    """

    def update(self) -> bool:
        pass

    observable_name: str
    scanner_name: str
    name: str = "phoneinfoga"
    # here is a list of pre declared api keys, user can put
    # values as per their required scanner, by default it is null

    numverifyapikey: str
    googlecse_cx: str
    googleapikey: str

    def run(self):
        response: None
        url: str = f"http://phoneinfoga:5000/api/v2/scanners/{self.scanner_name}/run"
        try:
            response = requests.post(
                url,
                headers={
                    "Content-Type": "application/json",
                    "accept": "application/json",
                },
                json={
                    "number": self.observable_name,
                    "options": {
                        "NUMVERIFY_API_KEY": self.numverifyapikey,
                        "GOOGLECSE_CX": self.googlecse_cx,
                        "GOOGLE_API_KEY": self.googleapikey,
                    },
                },
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.exception("Error while querying phoneinfoga analyzer: {e}")
            raise AnalyzerRunException(e)
        return response.json()

    @staticmethod
    def mocked_docker_analyzer_post(*args, **kwargs):
        mockrespose = {
            "result": {
                "valid": True,
                "number": "33679368229",
                "local_format": "0679368229",
                "international_format": "+33679368229",
                "country_prefix": "+33",
                "country_code": "FR",
                "country_name": "France",
                "location": "",
                "carrier": "Orange France SA",
                "line_type": "mobile",
            }
        }
        return MockUpResponse(mockrespose, 200)
