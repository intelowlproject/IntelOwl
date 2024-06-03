# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import magic
from permhash.functions import (
    APK_MANIFEST_MIMETYPES,
    APK_MIMETYPES,
    CRX_MANIFEST_MIMETYPES,
    CRX_MIMETYPES,
    permhash_apk,
    permhash_apk_manifest,
    permhash_crx,
    permhash_crx_manifest,
)

from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class Permhash(FileAnalyzer):
    """
    Create permissions hash of APK, Chrome extensions,
    Android manifest and Chrome extension manifest files.
    """

    def run(self):
        result = {}
        mimetype = magic.from_file(self.filepath, mime=True)

        hash_val = ""

        if mimetype in APK_MIMETYPES:
            hash_val = permhash_apk(self.filepath)
        elif mimetype in APK_MANIFEST_MIMETYPES:
            hash_val = permhash_apk_manifest(self.filepath)
        elif mimetype in CRX_MIMETYPES:
            hash_val = permhash_crx(self.filepath)
        elif mimetype in CRX_MANIFEST_MIMETYPES:
            hash_val = permhash_crx_manifest(self.filepath)
        else:
            raise AnalyzerRunException(f"Mimetype {mimetype} not supported.")

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
        hash_val = "aad106ceb64ac2a636ddec77c3feed4c2ffc5c27ab353660d8cb3e1c971ef278"
        patches = [
            if_mock_connections(
                patch(
                    "permhash.functions.permhash_apk",
                    return_value=hash_val,
                ),
                patch(
                    "permhash.functions.permhash_apk_manifest",
                    return_value=hash_val,
                ),
                patch(
                    "permhash.functions.permhash_crx",
                    return_value=hash_val,
                ),
                patch(
                    "permhash.functions.permhash_crx_manifest",
                    return_value=hash_val,
                ),
            )
        ]

        return super()._monkeypatch(patches=patches)
