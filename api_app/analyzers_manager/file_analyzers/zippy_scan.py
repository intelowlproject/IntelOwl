# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging

from zippy import CompressionEngine, EnsembledZippy, Zippy

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

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
        z = Zippy(engine=self.ENGINES[self.engine]) if self.engine in self.ENGINES else EnsembledZippy()

        logger.info(f"Running Zippy on file {self.filepath} using {self.engine}")
        binary_data = self.read_file_bytes()
        try:
            text_data = binary_data.decode("utf-8")
            response = z.run_on_file_chunked(filename=self.filepath)
        except UnicodeDecodeError:
            logger.exception(f"Cannot decode file {self.filepath}")
            raise AnalyzerRunException("Cannot decode file")
        except Exception as e:
            logger.exception(f"%{self.engine}.run_on_text_chunked(text_data) failed: {e}")
            raise AnalyzerRunException(f"{self.engine} failed")
        response = response + (text_data, "engine used: " + self.engine)
        # returning a response tuple with the text checked and AI or HUMAN
        return response
