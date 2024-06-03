import logging
import re

import requests

from api_app.analyzers_manager import classes
from tests.mock_utils import MockUpResponse, if_mock_connections, patch

logger = logging.getLogger(__name__)


class CyCat(classes.ObservableAnalyzer):
    """
    This analyzer is a wrapper for cycat api.
    """

    def update(self) -> bool:
        pass

    url: str = "https://api.cycat.org"

    def uuid_lookup(self, uuid: str):
        logger.info(
            f"performing lookup on uuid: {uuid}, observable: {self.observable_name}"
        )
        response = requests.get(
            self.url + "/lookup/" + uuid,
            headers={"accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()

    def run(self):
        final_response = {}
        uuid_pattern = re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
            re.IGNORECASE,
        )
        if uuid_pattern.match(self.observable_name):
            final_response = self.uuid_lookup(self.observable_name)

        else:
            response = requests.get(
                self.url + "/search/" + self.observable_name,
                headers={"accept": "application/json"},
            )
            response.raise_for_status()
            response = response.json()
            for uuid in response:
                final_response[uuid] = self.uuid_lookup(uuid)
        return final_response

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "requests.get",
                    return_value=MockUpResponse(
                        {
                            "description": """Detects Execution via
                            SyncInvoke in CL_Invocation.ps1 module""",
                            "raw": """
                            author: oscd.community, Natalia Shornikova
                            date: 2020/10/14
                            description: Detects Execution via
                            SyncInvoke in CL_Invocation.ps1 module
                            detection:
                            condition: selection
                            selection:
                                EventID: 4104
                                ScriptBlockText|contains|all:
                                - CL_Invocation.ps1
                                - SyncInvoke
                            falsepositives:
                            - Unknown
                            id: 4cd29327-685a-460e-9dac-c3ab96e549dc
                            level: high
                            logsource:
                            product: windows
                            service: powershell
                            modified: 2021/05/21
                            references:
                            - https://twitter.com/bohops/status/948061991012327424
                            status: experimental
                            tags:
                            - attack.defense_evasion
                            - attack.t1216
                            title: Execution via CL_Invocation.ps1
                            """,
                            "sigma:id": "4cd29327-685a-460e-9dac-c3ab96e549dc",
                            "title": "Execution via CL_Invocation.ps1",
                            "_cycat_type": "Item",
                        },
                        200,
                    ),
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
