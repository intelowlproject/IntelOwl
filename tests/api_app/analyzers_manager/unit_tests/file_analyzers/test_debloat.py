# tests/api_app/analyzers_manager/unit_tests/file_analyzers/test_debloat.py
from pathlib import Path
from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.debloat import Debloat
from tests.api_app.analyzers_manager.unit_tests.file_analyzers.base_test_class import (
    BaseFileAnalyzerTest,
)


class DebloatTestCase(BaseFileAnalyzerTest):
    analyzer_class = Debloat

    @staticmethod
    def get_mocked_response():
        pe_patch = patch(
            "api_app.analyzers_manager.file_analyzers.debloat.pefile.PE",
            return_value=MagicMock(name="FakePE"),
        )

        def _fake_process_pe(_binary, out_path=None, **_kwargs):
            Path(out_path).write_bytes(b"FAKE_DEBLOATED_PE")
            return 1

        proc_patch = patch(
            "api_app.analyzers_manager.file_analyzers.debloat.process_pe",
            side_effect=_fake_process_pe,
        )

        return [pe_patch, proc_patch]
