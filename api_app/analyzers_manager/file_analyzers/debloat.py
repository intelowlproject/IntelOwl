# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
import os
from base64 import b64encode

import debloat

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class Debloat(FileAnalyzer):
    def run(self):
        file_path = self.filepath  # Get the file path
        output_file = f"{file_path}.debloated"

        result = dict()
        try:
            logger.info(f"Running Debloat on {file_path}")
            binary = self.read_file_bytes()
            file_size = os.path.getsize(file_path)

            debloat.processor.process_pe(
                binary,
                out_path=str(output_file),
                last_ditch_processing=True,
                cert_preservation=True,
                log_message=print,
                beginning_file_size=file_size,
            )

            if not os.path.exists(output_file) or os.path.isdir(output_file):
                result["error"] = "Debloat failed to produce output"
                return result

            with open(output_file, "rb") as f:
                output = f.read()

            output_size = (
                os.path.getsize(output_file) if os.path.exists(output_file) else None
            )

            result["original_size"] = os.path.getsize(file_path)
            result["debloated_size"] = output_size
            result["debloated_file"] = b64encode(output).decode("utf-8")

        except Exception as e:
            result["error"] = str(e)
            logger.error(f"Debloat analysis failed: {e}")

        return result
