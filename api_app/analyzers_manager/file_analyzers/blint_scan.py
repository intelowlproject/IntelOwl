import logging

from blint.analysis import AnalysisRunner
from django.conf import settings

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class BlintAnalyzer(FileAnalyzer):
    """
    Wrapper for Blint static analysis tool
    """

    def update(self) -> bool:
        pass

    def run(self) -> dict:
        logger.info(f"Running Blint on {self.filepath}")
        # Blint requires a report directory
        # that we create during the docker build at
        # /opt/deploy/files_required/reports
        reports_dir = f"{settings.MEDIA_ROOT}/reports"
        analyzer = AnalysisRunner()
        response = analyzer.start(files=[self.filepath], reports_dir=reports_dir)
        if response == ([], [], []):
            return "No issues found"
        return {
            "findings": response[0],
            "reviews": response[1],
            "fuzzables": response[2],
        }
