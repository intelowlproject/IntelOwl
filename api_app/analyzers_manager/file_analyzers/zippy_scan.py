# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from zippy import EnsembledZippy

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import patch

logger = logging.getLogger(__name__)


class ZippyAnalyser(FileAnalyzer):
    """
    Tells if a file is written by HUMAN or AI
    """

    def run(self):
        binary_data = self.read_file_bytes()
        text_data = binary_data.decode("utf-8")
        try:
            response = EnsembledZippy().run_on_text_chunked(text_data)
        except Exception:
            logger.exception(
                "EnsembledZippyZippy().run_on_text_chunked(text_data) failed"
            )
            raise AnalyzerRunException
        # returning a response tuple with the text checked and AI or HUMAN
        return response + (text_data,)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            patch(
                "zippy.Zippy.run_on_text_chunked",
                return_value={"mocked_response": "AI 0.62739394"},
            ),
        ]
        return super()._monkeypatch(patches=patches)
