# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import logging
import os
from base64 import b64encode
from tempfile import TemporaryDirectory

import pefile
from debloat.processor import process_pe

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Debloat(FileAnalyzer):

    def run(self):
        try:
            binary = pefile.PE(self.filepath, fast_load=True)
        except pefile.PEFormatError as e:
            raise AnalyzerRunException(f"Invalid PE file: {e}")

        # BBOT logger is passing invalid kwargs to logger.info like "end" and "flush"
        def log_message(*args, end="\n", **kwargs):
            message = " ".join(map(str, args))
            if end:
                message += end
            valid_kwargs = {}
            for key, value in kwargs.items():
                if key in [
                    "level",
                    "exc_info",
                    "stack_info",
                    "extra",
                    "msg",
                    "args",
                    "kwargs",
                ]:
                    valid_kwargs[key] = value
            logger.info(message, **valid_kwargs)

        with TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "debloated.exe")
            original_size = os.path.getsize(self.filepath)

            try:
                debloat_code = process_pe(
                    binary,
                    out_path=output_path,
                    last_ditch_processing=True,
                    cert_preservation=True,
                    log_message=log_message,
                    beginning_file_size=original_size,
                )
            except Exception as e:
                raise AnalyzerRunException(f"Debloat processing failed: {e}")

            if debloat_code == 0 and not os.path.exists(output_path):
                return {
                    "success": False,
                    "error": "No solution found",
                }

            if not os.path.exists(output_path) or not os.path.isfile(output_path):
                raise AnalyzerRunException(
                    "Debloat did not produce a valid output file"
                )

            debloated_size = os.path.getsize(output_path)
            size_reduction = (
                (original_size - debloated_size) / original_size * 100
                if original_size > 0
                else 0
            )

            with open(output_path, "rb") as f:
                output = f.read()
                debloated_hash = hashlib.md5(output).hexdigest()

            encoded_output = b64encode(output).decode("utf-8")

            os.remove(output_path)
            logger.info("Cleaned up temporary file.")

            return {
                "success": True,
                "original_size": original_size,
                "debloated_size": debloated_size,
                "debloated_file": encoded_output,
                "size_reduction_percentage": size_reduction,
                "debloated_hash": debloated_hash,
            }

    @classmethod
    def update(cls) -> bool:
        pass

    @classmethod
    def _monkeypatch(cls, patches: list = None):
        patches = [
            if_mock_connections(
                patch(
                    "debloat.processor.process_pe",
                    return_value=MockUpResponse(
                        {
                            "success": True,
                            "original_size": 3840392,
                            "debloated_file": "TVqQAAMAAAAEAAAA//",
                            "debloated_hash": "f7f92eadfb444e7fce27efa2007a955a",
                            "debloated_size": 813976,
                            "size_reduction_percentage": 78.80487200264973,
                        },
                        200,
                    ),
                )
            ),
        ]
        return super()._monkeypatch(patches)
