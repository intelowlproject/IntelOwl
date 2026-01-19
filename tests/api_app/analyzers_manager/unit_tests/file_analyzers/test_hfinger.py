from unittest.mock import patch

from api_app.analyzers_manager.file_analyzers.hfinger import Hfinger

from .base_test_class import BaseFileAnalyzerTest


class TestHfinger(BaseFileAnalyzerTest):
    analyzer_class = Hfinger

    def get_mocked_response(self):
        return [
            patch(
                "hfinger.analysis.hfinger_analyze",
                return_value=[
                    {
                        "epoch_time": "1388111476.787707000",
                        "ip_src": "192.168.1.138",
                        "ip_dst": "173.194.115.80",
                        "port_src": "49209",
                        "port_dst": "80",
                        "fingerprint": "fp1",
                    },
                    {
                        "epoch_time": "1388111477.142485000",
                        "ip_src": "192.168.1.138",
                        "ip_dst": "66.225.230.141",
                        "port_src": "49220",
                        "port_dst": "80",
                        "fingerprint": "fp2",
                    },
                ],
            )
        ]
