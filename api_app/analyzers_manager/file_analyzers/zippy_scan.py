# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from zippy import CompressionEngine, EnsembledZippy, Zippy

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import patch

logger = logging.getLogger(__name__)


class ZippyAnalyser(FileAnalyzer):
    """
    Tells if a file is written by HUMAN or AI
    """

    engine: str

    def update(self):
        pass

    def run(self):
        z = None
        if self.engine == "lzma":
            z = Zippy(engine=CompressionEngine.LZMA)
        elif self.engine == "zlib":
            z = Zippy(engine=CompressionEngine.ZLIB)
        elif self.engine == "brotli":
            z = Zippy(engine=CompressionEngine.BROTLI)
        else:
            z = EnsembledZippy()

        logger.info("Running Zippy on file %s using %s", self.filepath, self.engine)
        binary_data = self.read_file_bytes()
        text_data = binary_data.decode("utf-8")
        filename = self.filepath
        logger.info("")
        try:
            response = z.run_on_file_chunked(filename)
        except Exception:
            logger.exception("%s.run_on_text_chunked(text_data) failed", self.engine)
            raise AnalyzerRunException
        # returning a response tuple with the text checked and AI or HUMAN
        return response + (text_data,)

    @classmethod
    def _monkeypatch(cls):
        patches = [
            patch(
                "EnsembledZippy().run_on_text_chunked",
                return_value={"mocked_response": "AI 0.62739394"},
            ),
        ]
        return super()._monkeypatch(patches=patches)
