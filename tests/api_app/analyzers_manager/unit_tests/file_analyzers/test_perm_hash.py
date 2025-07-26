from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.perm_hash import Permhash

from .base_test_class import BaseFileAnalyzerTest


class TestPermhash(BaseFileAnalyzerTest):
    analyzer_class = Permhash

    def get_mocked_response(self):
        """
        Mock the permhash functions to return a consistent hash value
        for all supported file types (APK, CRX, and their manifests).
        """
        hash_val = "aad106ceb64ac2a636ddec77c3feed4c2ffc5c27ab353660d8cb3e1c971ef278"

        return [
            patch("permhash.functions.permhash_apk", return_value=hash_val),
            patch("permhash.functions.permhash_apk_manifest", return_value=hash_val),
            patch("permhash.functions.permhash_crx", return_value=hash_val),
            patch("permhash.functions.permhash_crx_manifest", return_value=hash_val),
        ]
