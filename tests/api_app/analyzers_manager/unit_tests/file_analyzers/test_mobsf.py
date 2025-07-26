from api_app.analyzers_manager.file_analyzers.mobsf import Mobsf
from tests.mock_utils import MockUpResponse, patch

from .base_test_class import BaseFileAnalyzerTest


class TestMobsf(BaseFileAnalyzerTest):
    analyzer_class = Mobsf

    def get_mocked_response(self):
        return patch(
            "api_app.analyzers_manager.classes.DockerBasedAnalyzer._docker_run",
            return_value=MockUpResponse(
                {
                    "report": {
                        "md5": "d41d8cd98f00b204e9800998ecf8427e",
                        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                        "sha256": "e3b0c44298fc1c149afbf4c8996fb924",
                    }
                },
                200,
            ),
        )
