import logging
import os
from base64 import b64encode
from typing import Dict

import debloat.processor

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Debloat(FileAnalyzer):
    """
    Analyzer for debloating PE files using the Debloat tool.
    Reduces file size for easier malware analysis.
    """

    def run(self) -> Dict[str, int | str]:
        logger.info(f"Running Debloat analyzer on file {self.md5}")
        """
        Run the Debloat analyzer on the file.

        Returns:
            dict: A dictionary containing the original size, debloated size,
                  and the base64-encoded debloated file.

        Raises:
            AnalyzerRunException: If debloating fails or file processing errors occur.
        """
        try:
            binary = self.read_file_bytes()
            logger.info(f"Read {len(binary)} bytes from file {self.md5}")
            original_size = len(binary)
            logger.info(f"Read {original_size} bytes from file {self.md5}")
            logger.info(
                f"Starting Debloat on file {self.md5}, Initial size: {original_size} bytes"
            )

            output_file = f"{self.filepath}.debloated"
            logger.info(f"Output file: {output_file}")

            debloat.processor.process_pe(
                binary,
                out_path=str(output_file),
                last_ditch_processing=True,
                log_message=logger.info,
                cert_preservation=True,
                beginning_file_size=original_size,
            )
            logger.info(f"Debloat processing completed for file {self.md5}")

            if not os.path.exists(output_file) or os.path.isdir(output_file):
                raise AnalyzerRunException(
                    "Debloat failed to produce a valid output file"
                )

            with open(output_file, "rb") as f:
                output = f.read()

            debloated_size = len(output)
            logger.info(
                f"Completed debloating file {self.md5}, Final size: {debloated_size} bytes"
            )
            logger.info(
                f"Size reduction achieved: {original_size - debloated_size} bytes"
            )

            encoded_output = b64encode(output).decode("utf-8")

            os.remove(output_file)
            logger.info(f"Cleaned up temporary file: {output_file}")

            return {
                "original_size": original_size,
                "debloated_size": debloated_size,
                "debloated_file": encoded_output,
            }
        except Exception as e:
            raise AnalyzerRunException(f"Debloat failed: {e}") from e

    def update(self) -> bool:
        pass

    @classmethod
    def _monkeypatch(cls, patches: list = None):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse({}, 200),
                ),
                patch(
                    "requests.post",
                    return_value=MockUpResponse({}, 200),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
