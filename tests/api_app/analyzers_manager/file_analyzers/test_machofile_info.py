# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.


from api_app.analyzers_manager.file_analyzers.machofile_info import MachoFileInfo
from tests.api_app.analyzers_manager.file_analyzers.base_test_class import (
    BaseFileAnalyzerTest,
)


class TestMachoFileInfo(BaseFileAnalyzerTest):
    analyzer_class = MachoFileInfo

    def get_mocked_response(self):
        return []
