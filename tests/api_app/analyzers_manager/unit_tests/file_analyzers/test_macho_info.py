from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.macho_info import MachoInfo
from api_app.analyzers_manager.models import AnalyzerConfig
from api_app.choices import TLP, PythonModuleBasePaths
from api_app.models import PythonModule

from .base_test_class import BaseFileAnalyzerTest


class TestMachoInfo(BaseFileAnalyzerTest):
    analyzer_class = MachoInfo

    @classmethod
    def get_sample_file_path(cls, mimetype: str) -> str:
        if mimetype != "application/x-mach-binary":
            raise ValueError(f"No test file defined for mimetype {mimetype}")
        return "/tmp/test_macho"

    @classmethod
    def get_sample_file_bytes(cls, mimetype: str) -> bytes:
        if mimetype != "application/x-mach-binary":
            raise ValueError(f"No test bytes defined for mimetype {mimetype}")
        return b"fake macho bytes"

    @classmethod
    def setUpTestData(cls):
        super().setUpTestData()
        python_module, _ = PythonModule.objects.get_or_create(
            module="macho_info.MachoInfo",
            base_path=PythonModuleBasePaths.FileAnalyzer.value,
            defaults={
                "update_schedule": None,
                "health_check_schedule": None,
            },
        )
        AnalyzerConfig.objects.get_or_create(
            name="MachoInfo",
            python_module=python_module,
            defaults={
                "description": "Static Mach-O analysis",
                "disabled": False,
                "soft_time_limit": 30,
                "routing_key": "local",
                "health_check_status": True,
                "type": "file",
                "docker_based": False,
                "maximum_tlp": TLP.RED,
                "observable_supported": [],
                "supported_filetypes": ["application/x-mach-binary"],
                "run_hash": False,
                "run_hash_type": "",
                "not_supported_filetypes": [],
                "mapping_data_model": {},
            },
        )

    def get_mocked_response(self):
        mock_macho = MagicMock()
        mock_macho.get_general_info.return_value = {"file_type": "MH_EXECUTE"}
        mock_macho.get_macho_header.return_value = {"magic": "0xfeedfacf"}
        mock_macho.get_architectures.return_value = ["x86_64"]
        mock_macho.get_load_commands.return_value = [{"cmd": "LC_SEGMENT_64"}]
        mock_macho.get_load_commands_set.return_value = ["LC_SEGMENT_64"]
        mock_macho.get_segments.return_value = [{"name": "__TEXT"}]
        mock_macho.get_imported_functions.return_value = ["_printf"]
        mock_macho.get_exported_symbols.return_value = ["_main"]
        mock_macho.get_dylib_names.return_value = ["/usr/lib/libSystem.B.dylib"]
        mock_macho.get_entry_point.return_value = {"entryoff": 4096}
        mock_macho.get_uuid.return_value = "12345678-1234-1234-1234-1234567890ab"
        mock_macho.get_version_info.return_value = {"platform": "macOS"}
        mock_macho.get_similarity_hashes.return_value = {"symhash": "deadbeef"}
        mock_macho.get_import_hash.return_value = "importhash"
        mock_macho.get_export_hash.return_value = "exporthash"
        mock_macho.get_dylib_hash.return_value = "dylibhash"
        mock_macho.get_symhash.return_value = "symhash"
        mock_macho.get_code_signature_info.return_value = {"signed": False}

        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.macho_info.machofile.UniversalMachO",
                return_value=mock_macho,
            )
        ]
