import subprocess
import logging
import json
from shutil import which

from api_app.exceptions import AnalyzerRunException
from api_app.analyzers_manager.classes import FileAnalyzer


logger = logging.getLogger(__name__)


class ClamAV(FileAnalyzer):
    command: str = "clamdscan"

    def run(self):
        if not which(self.command):
            raise AnalyzerRunException("clamav not installed!")

        final_report = {}
        args = [self.command, self.filepath]

        process = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        logger.warning(stderr.decode("utf-8"))
        final_report["error"] = stderr.decode("utf-8")

        scan_report = stdout.decode("utf-8"), stderr
        scan_str = scan_report[0]

        try:
            if scan_str:
                data = json.loads(scan_str)
                final_report["data"] = data
        except ValueError as e:
            raise AnalyzerRunException(f"scan_str: {scan_str}. Error: {e}")

        return final_report
