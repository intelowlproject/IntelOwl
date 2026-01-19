# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from wad.detection import Detector

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException

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
