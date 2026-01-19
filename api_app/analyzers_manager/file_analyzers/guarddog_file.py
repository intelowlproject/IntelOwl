import json
import logging
import subprocess
from shlex import quote

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class GuardDogFile(FileAnalyzer):
    scan_type: str
    is_requirements_file: bool

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        # "verify" mode scans requirements file while "scan" mode scans .tar.gz file
        scan_mode = "verify" if self.is_requirements_file else "scan"

        try:
            process: subprocess.CompletedProcess = subprocess.run(
                [
                    "/usr/local/bin/guarddog",
                    quote(self.scan_type),
                    scan_mode,
                    quote(self.filepath),
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
