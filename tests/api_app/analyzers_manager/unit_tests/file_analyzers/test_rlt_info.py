# RTFInfo Test Class
from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.rtf_info import RTFInfo

from .base_test_class import BaseFileAnalyzerTest


class TestRTFInfo(BaseFileAnalyzerTest):
    analyzer_class = RTFInfo

    def get_extra_config(self):
        return {}

    def get_mocked_response(self):
        # Create mock RTF objects
        mock_rtf_obj1 = MagicMock()
        mock_rtf_obj1.is_ole = True
        mock_rtf_obj1.class_name = b"OLE2Link"
        mock_rtf_obj1.format_id = 2
        mock_rtf_obj1.oledata_size = 1024
        mock_rtf_obj1.is_package = False
        mock_rtf_obj1.oledata_md5 = "abc123def456"
        mock_rtf_obj1.clsid = "00000000-0000-0000-C000-000000000046"
        mock_rtf_obj1.clsid_desc = "OLE Link Object"

        mock_rtf_obj2 = MagicMock()
        mock_rtf_obj2.is_ole = True
        mock_rtf_obj2.class_name = b"Equation.3"
        mock_rtf_obj2.format_id = 1
        mock_rtf_obj2.oledata_size = 2048
        mock_rtf_obj2.is_package = True
        mock_rtf_obj2.filename = "malicious.exe"
        mock_rtf_obj2.src_path = "C:\\temp\\malicious.exe"
        mock_rtf_obj2.temp_path = "C:\\temp\\temp123.tmp"
        mock_rtf_obj2.olepkgdata_md5 = "def456ghi789"
        mock_rtf_obj2.clsid = None

        # Create mock parser instance
        mock_parser_instance = MagicMock()
        mock_parser_instance.objects = [mock_rtf_obj1, mock_rtf_obj2]
        mock_parser_instance.parse.return_value = None

        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.rtf_info.RtfObjParser",
                return_value=mock_parser_instance,
            ),
        ]
