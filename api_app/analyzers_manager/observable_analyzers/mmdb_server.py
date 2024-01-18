import logging

import requests

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import (  # AnalyzerConfigurationException
    AnalyzerRunException,
)
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class MmdbServer(classes.ObservableAnalyzer):
    base_url = "https://ip.circl.lu/geolookup/"

    def run(self):
        logger.info("nilay1")
        observable_ip = self.observable_name
        logger.info("nilay2")
        try:
            response = requests.get(self.base_url + observable_ip)
            # response.raise_for_status()
            logger.info("End point was hit")
        except requests.RequestException as e:
            logger.info("An error occured")
            raise AnalyzerRunException(e)
        logger.info(response)
        return response.json()

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
