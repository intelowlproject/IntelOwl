from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.zippy_scan import ZippyAnalyser

from .base_test_class import BaseFileAnalyzerTest


class TestZippyAnalyser(BaseFileAnalyzerTest):
    analyzer_class = ZippyAnalyser

    def get_extra_config(self):
        return {
            "engine": "lzma",
        }

    def get_mocked_response(self):
        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.zippy_scan.Zippy.run_on_file_chunked",
                return_value=("AI",),
            )
        ]
