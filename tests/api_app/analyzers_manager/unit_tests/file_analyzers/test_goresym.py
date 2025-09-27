from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.goresym import GoReSym

from .base_test_class import BaseFileAnalyzerTest


class TestGoReSym(BaseFileAnalyzerTest):
    analyzer_class = GoReSym

    def get_extra_config(self):
        return {
            "default": True,
            "paths": False,
            "types": False,
            "manual": "",
            "version": "",
        }

    def get_mocked_response(self):
        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.goresym.GoReSym._docker_run",
                return_value={
                    "report": {
                        "Version": "1.22.3",
                        "OS": "linux",
                        "BuildInfo": {
                            "GoVersion": "go1.22.3",
                            "Path": "github.com/example/project",
                        },
                    }
                },
            )
        ]
