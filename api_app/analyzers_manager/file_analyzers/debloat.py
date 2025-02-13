# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


import subprocess

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch


class DebloatAnalyzer(FileAnalyzer):
    """
    DebloatAnalyzer:
    This analyzer uses the Debloat tool to process large files by removing unnecessary data.
    It inherits common file handling and logging methods from FileAnalyzer.
    """

    tool_name: str = "Debloat"

    @classmethod
    def update(cls) -> bool:
        # Minimal implementation to satisfy the abstract method requirement.
        return True

    def run(self):
        try:
            file_path = self.filepath
            if not file_path:
                raise AnalyzerRunException("File path not found.")

            command = ["debloat", file_path, "--output", file_path + "_cleaned"]
            process = subprocess.run(
                command, capture_output=True, text=True, timeout=300, check=False
            )

            if process.returncode != 0:
                raise AnalyzerRunException(
                    f"Debloat failed with error: {process.stderr}"
                )

            return {
                "status": "success",
                "message": "Debloat successfully cleaned the file.",
            }

        except subprocess.TimeoutExpired:
            raise AnalyzerRunException("Debloat took too long to process the file.")
        except Exception as e:
            raise AnalyzerRunException(f"Debloat failed with error: {str(e)}")

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "subprocess.run",
                    return_value=MockUpResponse({"status": "success"}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
