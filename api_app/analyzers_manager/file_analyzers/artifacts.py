import logging

from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from tests.mock_utils import MockUpResponse

logger = logging.getLogger(__name__)


class Artifacts(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "apk_analyzer"
    url: str = "http://malware_tools_analyzers:4002/artifacts"
    # interval between http request polling
    poll_distance: int = 2
    # http request polling max number of tries
    max_tries: int = 30

    def update(self) -> bool:
        pass

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}", "-a", "-r"]
        req_data = {"args": args}
        req_files = {fname: binary}
        logger.info(
            f"Running {self.analyzer_name} on {self.filename} with args: {args}"
        )
        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        return result

    # flake8: noqa
    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            {
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
                        "elapsed_time": 0.02,
                    },
                }
            },
            200,
        )
