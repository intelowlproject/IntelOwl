# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging
import os

from permhash.functions import (
    permhash_apk,
    permhash_apk_manifest,
    permhash_crx,
    permhash_crx_manifest,
)

from api_app.analyzers_manager.classes import FileAnalyzer

logger = logging.getLogger(__name__)


class Permhash(FileAnalyzer):
    """
    Create permissions hash of APK, Chrome extensions,
    Android manifest and Chrome extension manifest files.
    """

    def run(self):
        result = {}
        _, file_extension = os.path.splitext(self.filepath)

        logger.info(f"Started PERMHASH============================> {self.filepath}")

        file_extension = file_extension[1:]

        hash_val = ""

        if file_extension == "apk":
            hash_val = permhash_apk(self.filepath)
        elif file_extension == "xml":
            hash_val = permhash_apk_manifest(self.filepath)
        elif file_extension == "crx":
            hash_val = permhash_crx(self.filepath)
        elif file_extension == "json":
            hash_val = permhash_crx_manifest(self.filepath)
        else:
            result["error"] = "Invalid file extension."

        # permhash returns False if for some reason the hash value can't be found
        if hash_val:
            result["hash"] = hash_val
        else:
            result["error"] = "Could not find permissions in the file."

        return result

    @classmethod
    def update(cls) -> bool:
        pass

    @classmethod
    def _monkeypatch(cls):
        patches = []

        return super()._monkeypatch(patches=patches)
