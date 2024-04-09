import logging
import os

from blint.analysis import AnalysisRunner
from django.conf import settings

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class BlintAnalyzer(FileAnalyzer):
    reports_dir = os.path.join(settings.MEDIA_ROOT, "reports")

    def run(self):
        logger.info(f"Running Blint on {self.filepath}")
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
        analyzer = AnalysisRunner()

        return analyzer.start(files=[self.filepath], reports_dir=self.reports_dir)
