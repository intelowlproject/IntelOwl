import json
import logging
import subprocess
from shlex import quote

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class GuardDogGeneric(ObservableAnalyzer):
    scan_type: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        try:

            process: subprocess.CompletedProcess = subprocess.run(
                [
                    "/usr/local/bin/guarddog",
                    quote(self.scan_type),
                    "scan",
                    quote(self.observable_name),
                    "--output-format=json",
                ],
                capture_output=True,
                check=True,
                text=True,
            )
            output = json.loads(process.stdout)

            return output

        except subprocess.CalledProcessError as e:
            std_error = e.stderr
            logger.error(f"Failed to execute command: {e}, {std_error}")
            raise AnalyzerRunException(f"failed to run guarddog: {std_error}")
