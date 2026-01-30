# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import hashlib
import logging
import os
import sys
from base64 import b64encode
from tempfile import TemporaryDirectory

import pefile
from debloat.processor import process_pe

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# Custom logger to handle the debloat library's logging
def log_message(*args, end="\n", flush=False, **kwargs):
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
    # Emulate flush if requested
    if flush:
        for handler in logger.handlers:
            if hasattr(handler, "flush"):
                handler.flush()
                break
        else:
            # Fallback to stdout flush if no flushable handlers
            sys.stdout.flush()


class Debloat(FileAnalyzer):
    def run(self):
        try:
            binary = pefile.PE(self.filepath, fast_load=True)
        except pefile.PEFormatError as e:
            raise AnalyzerRunException(f"Invalid PE file: {e}")

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
            except OSError as e:
                raise AnalyzerRunException(f"File operation failed during Debloat processing: {e}")
            except ValueError as e:
                raise AnalyzerRunException(f"Invalid parameter in Debloat processing: {e}")
            except AttributeError as e:
                raise AnalyzerRunException(f"Debloat library error, possibly malformed PE object: {e}")

            logger.info(f"Debloat processed {self.filepath} with code {debloat_code}")

            if debloat_code == 0 and not os.path.exists(output_path):
                return {
                    "success": False,
                    "error": "No solution found",
                }

            if not os.path.exists(output_path) or not os.path.isfile(output_path):
                raise AnalyzerRunException("Debloat did not produce a valid output file")

            debloated_size = os.path.getsize(output_path)
            size_reduction = (
                (original_size - debloated_size) / original_size * 100 if original_size > 0 else 0
            )

            with open(output_path, "rb") as f:
                output = f.read()
                debloated_hash = hashlib.md5(output).hexdigest()
                debloated_sha256 = hashlib.sha256(output).hexdigest()

            encoded_output = b64encode(output).decode("utf-8")

            os.remove(output_path)
            logger.debug("Cleaned up temporary file.")

            return {
                "success": True,
                "original_size": original_size,
                "debloated_size": debloated_size,
                "debloated_file": encoded_output,
                "size_reduction_percentage": size_reduction,
                "debloated_hash": debloated_hash,
                "debloated_sha256": debloated_sha256,
            }

    @classmethod
    def update(cls) -> bool:
        pass
