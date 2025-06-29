from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.detectiteasy import DetectItEasy

from .base_test_class import BaseFileAnalyzerTest


class TestDetectItEasy(BaseFileAnalyzerTest):
    analyzer_class = DetectItEasy

    def get_mocked_response(self):
        # Mock the die.scan_file function to return a JSON string
        mock_json_response = """{
            "detects": [
                {
                    "filetype": "PE64",
                    "parentfilepart": "Header",
                    "values": [
                        {
                            "info": "Console64,console",
                            "name": "GNU linker ld (GNU Binutils)",
                            "string": "Linker: GNU linker ld (GNU Binutils)(2.28)[Console64,console]",
                            "type": "Linker",
                            "version": "2.28"
                        },
                        {
                            "info": "",
                            "name": "MinGW",
                            "string": "Compiler: MinGW",
                            "type": "Compiler",
                            "version": ""
                        },
                        {
                            "info": "NRV,brute",
                            "name": "UPX",
                            "string": "Packer: UPX(4.24)[NRV,brute]",
                            "type": "Packer",
                            "version": "4.24"
                        }
                    ]
                }
            ]
        }"""

        return patch("die.scan_file", return_value=mock_json_response)
