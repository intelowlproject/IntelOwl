from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.pe_info import PEInfo

from .base_test_class import BaseFileAnalyzerTest


class PEInfoTest(BaseFileAnalyzerTest):
    analyzer_class = PEInfo

    def get_mocked_response(self):
        """
        Mock all the external libraries that PEInfo uses:
        - pefile (PE analysis)
        - lief (binary parsing)
        - magic (file type detection)
        - dotnetfile (.NET analysis)
        - pyimpfuzzy (import fuzzy hashing)
        - PIL (icon processing)
        """

        # Mock magic library for file type detection
        mock_magic_output = "PE32 executable (GUI) Intel 80386, for MS Windows"

        # Mock pefile PE object
        mock_pe = MagicMock()
        mock_pe.get_imphash.return_value = "1234567890abcdef1234567890abcdef"
        mock_pe.get_warnings.return_value = []
        mock_pe.is_dll.return_value = False
        mock_pe.is_driver.return_value = False
        mock_pe.is_exe.return_value = True

        # Mock PE sections
        mock_section = MagicMock()
        mock_section.Name = b".text"
        mock_section.VirtualAddress = 0x1000
        mock_section.Misc_VirtualSize = 0x2000
        mock_section.SizeOfRawData = 0x2000
        mock_section.get_entropy.return_value = 6.5
        mock_pe.sections = [mock_section]

        # Mock PE headers
        mock_pe.FILE_HEADER.Machine = 0x14C  # x86
        mock_pe.FILE_HEADER.TimeDateStamp = 1640995200  # 2022-01-01
        mock_pe.OPTIONAL_HEADER.MajorOperatingSystemVersion = 6
        mock_pe.OPTIONAL_HEADER.MinorOperatingSystemVersion = 1
        mock_pe.OPTIONAL_HEADER.AddressOfEntryPoint = 0x1000
        mock_pe.OPTIONAL_HEADER.ImageBase = 0x400000

        # Mock import table
        mock_import_entry = MagicMock()
        mock_import_entry.dll = b"kernel32.dll"
        mock_import_symbol = MagicMock()
        mock_import_symbol.name = b"GetProcAddress"
        mock_import_entry.imports = [mock_import_symbol]
        mock_pe.DIRECTORY_ENTRY_IMPORT = [mock_import_entry]

        # Mock dump_dict for export table
        mock_pe.dump_dict.return_value = {
            "Exported symbols": [{"Name": b"ExportedFunction"}],
            "Flags": ["IMAGE_FILE_EXECUTABLE_IMAGE"],
        }

        # Mock DotNetPE for .NET analysis
        mock_dotnet_pe = MagicMock()
        mock_dotnet_pe.get_runtime_target_version.return_value = "v4.0.30319"
        mock_dotnet_pe.get_number_of_streams.return_value = 5
        mock_dotnet_pe.has_resources.return_value = True
        mock_dotnet_pe.is_mixed_assembly.return_value = False
        mock_dotnet_pe.has_native_entry_point.return_value = False
        mock_dotnet_pe.is_native_image.return_value = False
        mock_dotnet_pe.is_windows_forms_app.return_value = True

        # Mock lief binary for icon extraction
        mock_lief_binary = MagicMock()
        mock_resources_manager = MagicMock()
        mock_resources_manager.has_type.return_value = True
        mock_icon = MagicMock()
        mock_resources_manager.icons = [mock_icon]
        mock_lief_binary.resources_manager = mock_resources_manager

        # Mock PIL Image for dhashicon
        mock_image = MagicMock()
        mock_image.convert.return_value.resize.return_value = mock_image
        mock_image.getpixel.side_effect = lambda pos: 128 if pos[0] % 2 == 0 else 64

        # Mock pyimpfuzzy
        mock_impfuzzy_hash = "192:ABC123DEF456:XYZ789"

        return [
            # Mock pefile
            patch(
                "api_app.analyzers_manager.file_analyzers.pe_info.pefile.PE",
                return_value=mock_pe,
            ),
            # Mock magic
            patch(
                "api_app.analyzers_manager.file_analyzers.pe_info.magic.from_buffer",
                return_value=mock_magic_output,
            ),
            # Mock DotNetPE
            patch(
                "api_app.analyzers_manager.file_analyzers.pe_info.DotNetPE",
                return_value=mock_dotnet_pe,
            ),
            # Mock lief
            patch(
                "api_app.analyzers_manager.file_analyzers.pe_info.lief.parse",
                return_value=mock_lief_binary,
            ),
            # Mock PIL Image
            patch(
                "api_app.analyzers_manager.file_analyzers.pe_info.Image.open",
                return_value=mock_image,
            ),
            # Mock pyimpfuzzy
            patch(
                "api_app.analyzers_manager.file_analyzers.pe_info.pyimpfuzzy.get_impfuzzy",
                return_value=mock_impfuzzy_hash,
            ),
            # Mock os.remove to avoid file system operations
            patch("api_app.analyzers_manager.file_analyzers.pe_info.os.remove"),
        ]

    def get_extra_config(self) -> dict:
        """
        PEInfo doesn't require additional configuration
        """
        return {}
