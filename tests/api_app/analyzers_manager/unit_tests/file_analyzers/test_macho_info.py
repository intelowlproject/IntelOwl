from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.macho_info import MachoInfo

from .base_test_class import BaseFileAnalyzerTest


class MachoInfoTest(BaseFileAnalyzerTest):
    analyzer_class = MachoInfo

    def get_mocked_response(self):
        """
        Mock machofile library interactions
        """
        # Mock the MachO object
        mock_macho = MagicMock()

        # Mock attributes and methods
        mock_macho.get_general_info.return_value = {
            "Filename": "test_macho",
            "Filesize": 1024,
            "MD5": "hash_md5",
        }
        mock_macho.get_macho_header.return_value = {
            "magic": "MH_MAGIC_64",
            "cputype": "ARM 64-bit",
            "filetype": "EXECUTE",
        }

        mock_macho.get_architectures.return_value = ["ARM 64-bit"]

        mock_macho.load_commands = ["LC_SEGMENT_64", "LC_MAIN"]
        mock_macho.segments = ["__TEXT", "__DATA"]
        mock_macho.dylib_names = ["/usr/lib/libSystem.B.dylib"]
        mock_macho.uuid = "1234-5678"
        mock_macho.entry_point = "0x1000"
        mock_macho.version_info = "1.0.0"
        mock_macho.code_signature_info = {"signed": True}

        mock_macho.get_imported_functions.return_value = {"/usr/lib/libSystem.B.dylib": ["_printf"]}
        mock_macho.get_exported_symbols.return_value = {"<export_trie>": ["_main"]}

        mock_macho.get_similarity_hashes.return_value = {
            "dylib_hash": "hash1",
            "import_hash": "hash2",
        }

        return [
            # Mock machofile.MachO class
            patch(
                "machofile.MachO",
                return_value=mock_macho,
            ),
        ]

    def get_extra_config(self) -> dict:
        return {}
