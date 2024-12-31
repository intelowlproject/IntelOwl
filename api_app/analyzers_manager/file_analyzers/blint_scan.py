import logging
import os
import shutil

from blint.config import BlintOptions
from blint.lib.runners import AnalysisRunner
from blint.lib.utils import gen_file_list
from django.conf import settings

from api_app.analyzers_manager.classes import FileAnalyzer
from intel_owl.settings._util import set_permissions

logger = logging.getLogger(__name__)


class BlintAnalyzer(FileAnalyzer):
    """
    Wrapper for Blint static analysis tool
    """

    def update(self) -> bool:
        pass

    def run(self) -> dict:
        logger.info(f"Running Blint on {self.filepath} for {self.md5}")

        reports_dir = settings.BLINT_REPORTS_PATH / f"blint_analysis_{self.md5}"
        os.mkdir(reports_dir)
        set_permissions(reports_dir)

        analyzer = AnalysisRunner()
        # findings, reviews, fuzzables = analyzer.start(
        #     files=[self.filepath], reports_dir=reports_dir
        # )
        findings, reviews, fuzzables = analyzer.start(
            blint_options=BlintOptions(reports_dir=reports_dir),
            exe_files=gen_file_list(self.filepath),
        )
        response = {"findings": findings, "reviews": reviews, "fuzzables": fuzzables}

        shutil.rmtree(reports_dir)

        return response
