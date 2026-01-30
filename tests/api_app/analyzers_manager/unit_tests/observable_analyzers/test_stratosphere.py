from datetime import datetime
from unittest.mock import mock_open, patch

from api_app.analyzers_manager.observable_analyzers.stratosphere import Stratos
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)


class StratosTestCase(BaseAnalyzerTest):
    analyzer_class = Stratos

    @staticmethod
    def get_mocked_response():
        # Simulated file content with valid CSV headers and an IP entry
        fake_csv_content = "S.No,IP,Rating\n1,8.8.8.8,High\n"

        # Patch open() to return fake CSV for all three datasets
        mock_files = {
            "stratos_ip_blacklist_last24hrs.csv": fake_csv_content,
            "stratos_ip_blacklist_new_attacker.csv": fake_csv_content,
            "stratos_ip_blacklist_repeated_attacker.csv": fake_csv_content,
        }

        def file_open_side_effect(file, *args, **kwargs):
            filename = file.split("/")[-1]
            return mock_open(read_data=mock_files[filename])()

        patches = [
            patch("builtins.open", side_effect=file_open_side_effect),
            patch("os.path.isfile", return_value=True),
            patch("os.path.exists", return_value=True),
            patch("os.path.getctime", return_value=datetime.now().timestamp()),
        ]
        return patches

    @classmethod
    def get_extra_config(cls) -> dict:
        return {}  # Stratos doesn't need extra config
