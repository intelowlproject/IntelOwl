from api_app.analyzers_manager.file_analyzers.lnk_info import LnkInfo

from .base_test_class import BaseFileAnalyzerTest


class TestLnkInfo(BaseFileAnalyzerTest):
    analyzer_class = LnkInfo

    def get_mocked_response(self):
        # No patching needed for LnkInfo analyzer
        return None
