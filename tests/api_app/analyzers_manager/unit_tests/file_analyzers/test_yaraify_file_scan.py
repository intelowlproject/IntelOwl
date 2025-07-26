# from unittest.mock import patch
# from api_app.analyzers_manager.file_analyzers.yaraify_file_scan import YARAifyFileScan
# from tests.mock_utils import MockUpResponse
# from .base_test_class import BaseFileAnalyzerTest


# class TestYARAifyFileScan(BaseFileAnalyzerTest):
#     analyzer_class = YARAifyFileScan

#     def get_extra_config(self):
#         return {
#             "_api_key_identifier": "dummy-id",
#             "clamav_scan": True,
#             "unpack": True,
#             "share_file": False,
#             "skip_noisy": False,
#             "skip_known": False,
#         }

#     def get_mocked_response(self):
#         return patch(
#             "requests.post",
#             side_effect=[
#                 # First call: hash lookup
#                 MockUpResponse({"query_status": "not-available"}, 200),
#                 # Second call: sending file
#                 MockUpResponse(
#                     {"query_status": "queued", "data": {"task_id": "123"}}, 200
#                 ),
#                 # Third call: polling result
#                 MockUpResponse(
#                     {"query_status": "ok", "data": {"static_results": []}}, 200
#                 ),
#             ],
#         )
