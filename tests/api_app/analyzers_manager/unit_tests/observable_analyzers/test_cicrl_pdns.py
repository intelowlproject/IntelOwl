# from unittest.mock import patch
# from api_app.analyzers_manager.observable_analyzers.circl_pdns import (
#     CIRCL_PDNS,
# )
# from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
#     BaseAnalyzerTest,
# )
# from tests.mock_utils import MockResponseNoOp


# class CIRCL_PDNSTestCase(BaseAnalyzerTest):
#     analyzer_class = CIRCL_PDNS

#     @staticmethod
#     def get_mocked_response():
#         return patch("pypdns.PyPDNS", return_value=MockResponseNoOp({}, 200))

#     @classmethod
#     def get_extra_config(cls) -> dict:
#         return {
#             "_pdns_credentials": "test_user|test_password"
#         }

#     def _setup_analyzer(self, config, observable_type, observable_value):
#         """Override to ensure config() method is called"""
#         analyzer = super()._setup_analyzer(config, observable_type, observable_value)
#         # Call config method to initialize split_credentials
#         analyzer.config({})
#         return analyzer
