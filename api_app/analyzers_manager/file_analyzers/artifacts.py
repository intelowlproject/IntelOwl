from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from tests.mock_utils import MockUpResponse


class Artifacts(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "android_analyzer"
    url: str = "http://malware_tools_analyzers:4002/artifacts"
    # interval between http request polling
    poll_distance: int = 5
    # http request polling max number of tries
    max_tries: int = 5

    def update(self) -> bool:
        pass

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = []
        args.append(f"@{fname}")
        req_data = {"args": args}
        req_files = {fname: binary}
        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)

        return result

    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            {},
            200,
        )
