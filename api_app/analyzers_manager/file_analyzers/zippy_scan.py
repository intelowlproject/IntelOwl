# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from zippy import CompressionEngine, EnsembledZippy, Zippy

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

# from tests.mock_utils import MockResponseNoOp, patch

logger = logging.getLogger(__name__)


class ZippyAnalyser(FileAnalyzer):
    """
    Tells if a file is written by HUMAN or AI
    """

    ENGINES = {
        "lzma": CompressionEngine.LZMA,
        "zlib": CompressionEngine.ZLIB,
        "brotli": CompressionEngine.BROTLI,
    }

    engine: str

    def update(self):
        pass

    def run(self):
        z = (
            Zippy(engine=self.ENGINES[self.engine])
            if self.engine in self.ENGINES
            else EnsembledZippy()
        )

        logger.info("Running Zippy on file %s using %s", self.filepath, self.engine)
        binary_data = self.read_file_bytes()
        try:
            text_data = binary_data.decode("utf-8")
            response = z.run_on_file_chunked(filename=self.filepath)
        except UnicodeDecodeError:
            logger.exception("Cannot decode file %s", self.filepath)
            raise AnalyzerRunException("Cannot decode file")
        except Exception as e:
            logger.exception("%s.run_on_text_chunked(text_data) failed", self.engine)
            logger.exception(e)
            raise AnalyzerRunException(f"{self.engine} failed")
        response = response + (text_data, "engine used: " + self.engine)
        # returning a response tuple with the text checked and AI or HUMAN
        return response
