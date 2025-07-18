import json
import logging
from subprocess import CalledProcessError, CompletedProcess, run

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class GuardDogFile(FileAnalyzer):
    scan_type: str
    is_requirements_file: bool

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        scan_mode = "verify" if self.is_requirements_file else "scan"

        try:
            command: CompletedProcess = run(
                [
                    "guarddog",
                    self.scan_type,
                    scan_mode,
                    self.filepath,
                    "--output-format=json",
                ],
                capture_output=True,
            )
            std_error = command.stderr
            if std_error:
                std_error = std_error.decode("utf-8")
            command.check_returncode()  # raises CalledProcessError if return code is non-zero else none

            output = json.loads(command.stdout)

            return output

        except CalledProcessError as e:
            logger.error(f"Failed to execute command: {e}, {std_error}")
            raise AnalyzerRunException(f"failed to run guarddog: {std_error}")

    @classmethod
    def _monkeypatch(cls):

        response_from_command = CompletedProcess(
            args=[
                "guarddog",
                "pypi",
                "verify",
                "apkid-requirements.txt",
                "--output-format=json",
            ],
            returncode=0,
            stdout=b'[{"dependency": "requests", "version": "2.32.3", "result": {"issues": 0, "errors": {}, "results": {}}]',
            stderr=b"INFO: Scanning using at most 8 parallel worker threads\n\n",
        )

        patches = [
            if_mock_connections(
                patch("subprocess.run", return_value=response_from_command)
            )
        ]
        return super()._monkeypatch(patches)
