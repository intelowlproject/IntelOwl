from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.xlm_macro_deobfuscator import (
    XlmMacroDeobfuscator,
)

from .base_test_class import BaseFileAnalyzerTest


class TestXlmMacroDeobfuscator(BaseFileAnalyzerTest):
    analyzer_class = XlmMacroDeobfuscator

    def get_extra_config(self):
        return {"passwords_to_check": ["infected", "secret", ""]}

    def get_mocked_response(self):
        return patch(
            "api_app.analyzers_manager.file_analyzers.xlm_macro_deobfuscator.process_file",
            return_value="Deobfuscated macro content",
        )
