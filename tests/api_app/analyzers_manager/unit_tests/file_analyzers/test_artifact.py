from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.artifacts import Artifacts
from tests.api_app.analyzers_manager.unit_tests.file_analyzers.base_test_class import (
    BaseFileAnalyzerTest,
)


class ArtifactTestCase(BaseFileAnalyzerTest):
    analyzer_class = Artifacts

    @staticmethod
    def get_mocked_response():
        return patch(
            "api_app.analyzers_manager.file_analyzers.artifacts.Artifacts._docker_run",
            return_value={
                "report": {
                    "name": "APK_Artifacts",
                    "process_time": 5.07,
                    "status": "SUCCESS",
                    "end_time": "2024-08-27T10:03:15.563886Z",
                    "parameters": {},
                    "type": "analyzer",
                    "id": 72,
                    "report": {
                        "dex": ["classes.dex"],
                        "md5": "8a05a189e58ccd7275f7ffdf88c2c191",
                        "root": [],
                        "family": {
                            "name": "CryCrypto",
                            "match": 11.11,
                            "value": {
                                "intent": 33.33,
                                "permission": 0.0,
                                "application": 0.0,
                            },
                        },
                        "string": {"known": [], "base64": [], "telegram_id": []},
                        "library": [],
                        "network": {"ip": [], "url": [], "param": []},
                        "sandbox": [
                            "https://tria.ge/s?q=8a05a189e58ccd7275f7ffdf88c2c191",
                            "https://www.joesandbox.com/analysis/search?q=8a05a189e58ccd7275f7ffdf88c2c191",
                            "https://www.virustotal.com/gui/search/8a05a189e58ccd7275f7ffdf88c2c191",
                            "https://bazaar.abuse.ch/browse.php?search=md5:8a05a189e58ccd7275f7ffdf88c2c191",
                            "https://koodous.com/apks?search=8a05a189e58ccd7275f7ffdf88c2c191",
                        ],
                        "version": "1.1.1",
                        "elapsed_time": 0.02,  # Fixed this line
                    },
                },
            },
        )
