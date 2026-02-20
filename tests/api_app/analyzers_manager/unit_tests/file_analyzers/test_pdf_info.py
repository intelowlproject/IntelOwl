from unittest.mock import MagicMock, patch

from api_app.analyzers_manager.file_analyzers.pdf_info import PDFInfo

from .base_test_class import BaseFileAnalyzerTest


class PDFInfoTest(BaseFileAnalyzerTest):
    analyzer_class = PDFInfo

    def get_mocked_response(self):
        """
        Mock both peepdf and pdfid libraries since PDFInfo uses both
        """
        # Mock peepdf components
        mock_pdf = MagicMock()
        mock_pdf.getStats.return_value = {
            "Versions": [
                {
                    "Events": {"suspicious_event": 1},
                    "Actions": {"javascript": 2},
                    "Elements": {"/JS": 1, "/JavaScript": 1},
                    "Vulns": ["CVE-2023-1234"],
                    "Objects with JS code": [1, 2],
                }
            ]
        }
        mock_pdf.getURLs.return_value = [["http://example.com", "http://malicious.com"]]
        mock_pdf.getURIs.return_value = [["uri://test", "uri://sample"]]

        mock_parser = MagicMock()
        mock_parser.parse.return_value = (0, mock_pdf)  # 0 indicates success

        # Mock pdfid - create a realistic result structure
        mock_pdfid_result = {"reports": [{"/Page": 1, "/Count": 5, "/JS": 2, "/JavaScript": 1}]}

        # Create a mock options object that can have json attribute set
        class MockOptions:
            def __init__(self):
                self.json = True

        # Mock the entire pdfid module to avoid import issues
        mock_pdfid_module = MagicMock()
        mock_pdfid_module.get_fake_options.return_value = MockOptions()
        mock_pdfid_module.PDFiDMain.return_value = mock_pdfid_result

        return [
            patch("peepdf.PDFCore.PDFParser", return_value=mock_parser),
            patch(
                "api_app.analyzers_manager.file_analyzers.pdf_info.pdfid",
                mock_pdfid_module,
            ),
        ]

    def get_extra_config(self) -> dict:
        """
        PDFInfo doesn't require additional configuration
        """
        return {}
