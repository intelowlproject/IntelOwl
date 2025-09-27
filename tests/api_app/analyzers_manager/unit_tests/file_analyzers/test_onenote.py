import json
from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.onenote import OneNoteInfo

from .base_test_class import BaseFileAnalyzerTest


class TestOneNoteInfo(BaseFileAnalyzerTest):
    analyzer_class = OneNoteInfo

    def get_mocked_response(self):
        fake_onenote_output = {
            "files": {
                "1": {
                    "extension": ".docx",
                    "content": "48656c6c6f20576f726c64",  # "Hello World" in hex
                },
                "2": {
                    "extension": ".png",
                    "content": "89504e470d0a1a0a0000",  # dummy PNG content
                },
            },
            "metadata": {"author": "test_user"},
        }

        # `process_onenote_file` returns JSON string
        return patch(
            "api_app.analyzers_manager.file_analyzers.onenote.process_onenote_file",
            return_value=json.dumps(fake_onenote_output),
        )
