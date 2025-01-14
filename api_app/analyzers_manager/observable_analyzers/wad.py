# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from wad.detection import Detector

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class WAD(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for the WAD (Web Application Detector) project.
    """

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        logger.info(f"Running WAD Analyzer for {self.observable_name}")

        detector = Detector()

        results = detector.detect(url=self.observable_name)

        if results:
            return results
        else:
            raise AnalyzerRunException("no results returned for the provided url")

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(
                    Detector,
                    "detect",
                    return_value={
                        "https://www.google.com/": [
                            {
                                "app": "Google Web Server",
                                "ver": "null",
                                "type": "Web Servers",
                            }
                        ]
                    },
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
