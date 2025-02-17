import json
import logging

import die

from api_app.analyzers_manager.classes import FileAnalyzer
from tests.mock_utils import MockUpResponse

logger = logging.getLogger(__name__)


class DetectItEasy(FileAnalyzer):

    def update(self):
        pass

    def run(self):
        logger.info(f"Running DIE on {self.filepath} for {self.md5}")

        json_report = die.scan_file(
            self.filepath, die.ScanFlags.RESULT_AS_JSON, str(die.database_path / "db")
        )

        return json.loads(json_report)

    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            {
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
                                "version": "2.28",
                            },
                            {
                                "info": "",
                                "name": "MinGW",
                                "string": "Compiler: MinGW",
                                "type": "Compiler",
                                "version": "",
                            },
                            {
                                "info": "NRV,brute",
                                "name": "UPX",
                                "string": "Packer: UPX(4.24)[NRV,brute]",
                                "type": "Packer",
                                "version": "4.24",
                            },
                        ],
                    }
                ]
            },
            200,
        )
