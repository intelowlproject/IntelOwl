from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.mwdb_scan import MockUpMWDB, MWDB_Scan

from .base_test_class import BaseFileAnalyzerTest


class TestMWDBScan(BaseFileAnalyzerTest):
    analyzer_class = MWDB_Scan

    def get_mocked_response(self):
        # Patch mwdblib.MWDB to return our MockUpMWDB
        return patch(
            "api_app.analyzers_manager.file_analyzers.mwdb_scan.mwdblib.MWDB",
            return_value=MockUpMWDB(),
        )

    def get_extra_config(self):
        # Hardcode required config values
        return {
            "_api_key_name": "dummy_key",
            "private": False,
            "max_tries": 1,
            "session": None,
            "upload_file": True,
            "public": True,
        }
