import subprocess
import json
from shutil import which

from api_app.script_analyzers import classes
from api_app.exceptions import AnalyzerRunException


class CheckDMARC(classes.ObservableAnalyzer):
    check_command: str = "checkdmarc"

    def run(self):
        if not which(self.check_command):
            self.report["success"] = False
            raise AnalyzerRunException("checkdmarc not installed!")

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
