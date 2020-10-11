import logging
import speakeasy

from api_app.script_analyzers.classes import FileAnalyzer
from celery.exceptions import SoftTimeLimitExceeded

logger = logging.getLogger(__name__)


class SpeakEasy(FileAnalyzer):
    def run(self):
        results = {}
        s = speakeasy.Speakeasy()
        try:
            m = s.load_module(self.filepath)
            s.run_module(m)
            results = s.get_report()
        except SoftTimeLimitExceeded as e:
            error_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name} md5:{self.md5}"
                f"filename: {self.filename}. Soft Time Limit Exceeded Error {e}"
            )
            logger.error(error_message)
            self.report["errors"].append(str(e))
            self.report["success"] = False

        return results
