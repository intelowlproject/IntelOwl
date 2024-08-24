from api_app.analyzers_manager.classes import DockerBasedAnalyzer, FileAnalyzer
from tests.mock_utils import MockUpResponse


class Mobsf(FileAnalyzer, DockerBasedAnalyzer):
    name: str = "file_analyzer"
    url: str = "http://malware_tools_analyzers:4002/mobsf"
    # interval between http request polling
    poll_distance: int = 2
    # http request polling max number of tries
    max_tries: int = 5

    def update(self):
        pass

    def run(self):
        binary = self.read_file_bytes()
        fname = str(self.filename).replace("/", "_").replace(" ", "_")
        args = [f"@{fname}", "--json"]
        req_data = {"args": args}
        req_files = {fname: binary}

        result = self._docker_run(req_data, req_files, analyzer_name=self.analyzer_name)
        return result

    @staticmethod
    def mocked_docker_analyzer_get(*args, **kwargs):
        return MockUpResponse(
            # flake8: noqa
            {"results": {"test": "test"}},
            200,
        )
