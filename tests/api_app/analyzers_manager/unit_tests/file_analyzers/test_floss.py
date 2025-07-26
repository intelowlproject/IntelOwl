from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.floss import Floss

from .base_test_class import BaseFileAnalyzerTest


class TestFloss(BaseFileAnalyzerTest):
    analyzer_class = Floss

    def get_extra_config(self):
        return {
            "max_no_of_strings": {"decoded": 10, "stack": 5},
            "rank_strings": {"decoded": True, "stack": False},
        }

    def get_mocked_response(self):
        return [
            patch(
                "api_app.analyzers_manager.file_analyzers.floss.Floss._docker_run",
                side_effect=[
                    {
                        "strings": {
                            "decoded": ["de_string1", "de_string2"],
                            "stack": ["st_string1", "st_string2"],
                        }
                    },
                    # second call for ranking decoded strings only
                    ["de_string1", "de_string2"],  # simulate ranked strings
                ],
            ),
        ]
