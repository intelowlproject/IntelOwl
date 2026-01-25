from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.mobsf_service import MobSF_Service
from tests.mock_utils import MockUpResponse

from .base_test_class import BaseFileAnalyzerTest


class TestMobSFService(BaseFileAnalyzerTest):
    analyzer_class = MobSF_Service

    def get_extra_config(self):
        return {
            "_mobsf_api_key": "test_mobsf_api_key",
            "mobsf_host": "https://mock-mobsf.local",  # mocked host
            "enable_dynamic_analysis": False,  # can be toggled to True if needed
        }

    def get_mocked_response(self):
        return patch(
            "requests.post",
            return_value=MockUpResponse(
                {
                    "file_name": "diva-beta.apk",
                    "hash": "82ab8b2193b3cfb1c737e3a786be363a",
                    "scan_type": "apk",
                },
                200,
            ),
        )
