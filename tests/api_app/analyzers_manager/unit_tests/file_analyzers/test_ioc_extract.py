from api_app.analyzers_manager.file_analyzers.iocextract import IocExtract

from .base_test_class import BaseFileAnalyzerTest


class TestIocExtract(BaseFileAnalyzerTest):
    analyzer_class = IocExtract

    def get_mocked_response(self):
        # No patching required for IocExtract, as it uses only local logic
        return None
