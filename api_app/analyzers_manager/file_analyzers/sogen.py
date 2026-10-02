# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.
import logging
from typing import Any, Dict

import requests

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException

logger = logging.getLogger(__name__)

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024  # 50MB, generous for a PE sample


class Sogen(FileAnalyzer):
    """
    Emulates a PE binary using the Sogen emulator
    (https://github.com/momo5502/sogen) via the sogen_analyzer sidecar
    service, since Sogen's native build (a bundled QEMU/Unicorn/SDL fork)
    is too heavy and fragile to compile inside the main IntelOwl image.

    url_key_name is a required Parameter pointing at the sidecar,
    e.g. http://sogen_analyzer:4009 when run via docker-compose.
    """

    max_instructions: int = 20_000_000
    timeout_seconds: int = 60
    requests_timeout: int = 300
    url_key_name: str

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self) -> Dict[str, Any]:
        file_bytes = self.read_file_bytes()
        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            raise AnalyzerRunException(
                f"File too large for Sogen emulation: {len(file_bytes)} bytes (max {MAX_FILE_SIZE_BYTES})"
            )

        api_url = self.url_key_name.rstrip("/") + "/analyze"

        try:
            response = requests.post(
                api_url,
                files={"file": (self.filename, file_bytes)},
                data={
                    "max_instructions": self.max_instructions,
                    "timeout_seconds": self.timeout_seconds,
                },
                timeout=self.requests_timeout,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            raise AnalyzerRunException(f"Failed to reach Sogen sidecar: {e}")

        try:
            result = response.json()
        except ValueError as e:
            raise AnalyzerRunException(f"Sogen sidecar returned invalid JSON: {e}")

        if result.get("error"):
            raise AnalyzerRunException(f"Sogen emulation failed: {result['error']}")

        return result
