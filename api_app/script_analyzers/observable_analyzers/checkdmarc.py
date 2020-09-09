import subprocess
import logging
import json

from api_app.script_analyzers import classes

logger = logging.getLogger(__name__)


class CheckDMARC(classes.ObservableAnalyzer):
    check_command: str = "checkdmarc"

    def run(self):
        try:
            process = subprocess.Popen(
                [self.check_command, self.observable_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process.wait()
            stdout, stderr = process.communicate()

            dmarc_info = stdout.decode("utf-8"), stderr

            dmarc_str = dmarc_info[0]

            dmarc_json = json.loads(dmarc_str)

            return dmarc_json

        except OSError as e:
            error_message = (
                f"job_id:{self.job_id} analyzer:{self.analyzer_name} Error: {e}"
            )
            logger.error(error_message)
            self.report["errors"].append(error_message)
            self.report["success"] = False
