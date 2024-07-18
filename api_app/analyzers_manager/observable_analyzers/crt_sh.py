import logging

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class Crt_sh(classes.ObservableAnalyzer):
    """
    Wrapper of crt.sh
    """

    url = "https://crt.sh"

    def update(self):
        pass

    def run(self):
        headers = {"accept": "application/json"}
        response = requests.get(
            f"{self.url}/?q={self.observable_name}", headers=headers
        )
        response.raise_for_status()
        response = response.json()
        return response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "issuer_ca_id": 16418,
                            "issuer_name": """C=US, O=Let's Encrypt,
                             CN=Let's Encrypt Authority X3""",
                            "name_value": "hatch.uber.com",
                            "min_cert_id": 325717795,
                            "min_entry_timestamp": "2018-02-08T16:47:39.089",
                            "not_before": "2018-02-08T15:47:39",
                        },
                        200,
                    ),
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
