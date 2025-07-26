from api_app.analyzers_manager.file_analyzers.iocfinder import IocFinder

from .base_test_class import BaseFileAnalyzerTest


class TestIocFinder(BaseFileAnalyzerTest):
    analyzer_class = IocFinder

    def get_mocked_response(self):
        # No external requests, so nothing to patch
        return None
