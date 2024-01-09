# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from zippy import EnsembledZippy
from api_app.analyzers_manager.classes import FileAnalyzer
from api_app.analyzers_manager.exceptions import (
    AnalyzerRunException,
)
from tests.mock_utils import patch

class ZippyAnalyser(FileAnalyzer):
    """
    Tells if a file is written by HUMAN or AI
    """
    def run(self):
        binary_data=self.read_file_bytes()
        text_data = binary_data.decode('utf-8')
        try:
            response=(EnsembledZippy().run_on_text_chunked(text_data))
        except Exception as _:
            print("Zippy not imported correctly")
            raise AnalyzerRunException
        print(response)
        return response.json()

    @classmethod
    def _monkeypatch_zippy(cls):
        patches = [
            patch(
                'zippy.EnsembledZippy.run_on_text_chunked',
                return_value={'mocked_response': 'AI 0.62739394'}
            ),
        ]
        return super()._monkeypatch(patches=patches)




