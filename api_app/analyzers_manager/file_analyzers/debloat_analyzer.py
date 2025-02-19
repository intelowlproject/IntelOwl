# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
import os
from base64 import b64encode

import debloat.processor

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)


class Debloat(FileAnalyzer):
    def run(self):
        output_file = f"{self.filepath}.debloated"

        result = dict()
        try:
            binary = self.read_file_bytes()
            file_size = os.path.getsize(self.filepath)
            logger.info(
                f"Running Debloat on file: {self.md5}, Initial size: {file_size}"
            )

            debloat.processor.process_pe(
                binary,
                out_path=str(output_file),
                last_ditch_processing=True,
                cert_preservation=True,
                log_message=logger.info,
                beginning_file_size=file_size,
            )

            if not os.path.exists(output_file) or os.path.isdir(output_file):
                raise AnalyzerRunException("Debloat failed to produce an output file")

            output_size = os.path.getsize(output_file)

            with open(output_file, "rb") as f:
                output = f.read()

            logger.info(
                f"Finished debloating file: {self.md5}, Final size: {output_size}"
            )
            logger.info(f"Difference: {file_size - output_size}")

            result["original_size"] = os.path.getsize(self.filepath)
            result["debloated_size"] = output_size
            result["debloated_file"] = b64encode(output).decode("utf-8")
            return result

        except Exception as e:
            logger.error(f"Debloat analysis failed: {e}")
            raise AnalyzerRunException(f"Debloat analysis failed: {e}")
