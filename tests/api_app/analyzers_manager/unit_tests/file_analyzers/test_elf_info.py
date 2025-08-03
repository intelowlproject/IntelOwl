from unittest.mock import MagicMock, mock_open, patch

from elftools.construct import Container

from api_app.analyzers_manager.file_analyzers.elf_info import ELFInfo

from .base_test_class import BaseFileAnalyzerTest


class TestELFInfo(BaseFileAnalyzerTest):
    analyzer_class = ELFInfo

    def get_mocked_response(self):
        # Mock ELF file content and structure
        mock_elf = MagicMock()

        # Mock ELF header as Container object
        mock_e_ident = Container()
        mock_e_ident.EI_MAG = [0x7F, 0x45, 0x4C, 0x46]  # ELF magic number
        mock_e_ident.EI_CLASS = 2  # 64-bit
        mock_e_ident.EI_DATA = 1  # Little endian
        mock_e_ident.EI_VERSION = 1
        mock_e_ident.EI_OSABI = 0
        mock_e_ident.EI_ABIVERSION = 0

        mock_header = Container()
        mock_header.e_ident = mock_e_ident
        mock_header.e_type = 2  # ET_EXEC
        mock_header.e_machine = 62  # EM_X86_64
        mock_header.e_version = 1
        mock_header.e_entry = 0x400000
        mock_header.e_phoff = 64
        mock_header.e_shoff = 4096
        mock_header.e_flags = 0
        mock_header.e_ehsize = 64
        mock_header.e_phentsize = 56
        mock_header.e_phnum = 8
        mock_header.e_shentsize = 64
        mock_header.e_shnum = 29
        mock_header.e_shstrndx = 28

        # Configure mock ELF object
        mock_elf.header = mock_header
        mock_elf.elfclass = 64
        mock_elf.little_endian = True

        # Mock telfhash result
        mock_telfhash_result = (
            {
                "telfhash": "T1234567890ABCDEF1234567890ABCDEF12345678",
                "header": {
                    "machine": "x86_64",
                    "class": "ELF64",
                    "data": "little_endian",
                },
                "sections": [
                    {"name": ".text", "size": 1024},
                    {"name": ".data", "size": 512},
                ],
                "symbols": 42,
                "imports": 15,
                "exports": 8,
            },
        )

        # Create patches for all the dependencies
        patches = [
            patch("builtins.open", mock_open()),
            patch("elftools.elf.elffile.ELFFile", return_value=mock_elf),
            patch("telfhash.telfhash", return_value=mock_telfhash_result),
        ]

        return patches
