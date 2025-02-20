# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.observable_analyzers.phunter.phunter_base import (
    PhunterBase,
)
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class Phunter(ObservableAnalyzer):
    """
    This analyzer is a wrapper for the Phunter project.
    """

    @classmethod
    def update(cls) -> bool:
        pass

    def run(self):
        logger.info(f"Running Phunter Analyzer for {self.observable_name}")

        results = PhunterBase.phunt(phone_number=self.observable_name)

        return results

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch.object(
                    PhunterBase,
                    "phunt",
                    return_value={
                        "Valid": "true",
                        "Operator": "Not found",
                        "Possible": "true",
                        "Line Type": "Not found",
                        "Spamcalls": "true",
                        "Free Lookup": {
                            "Owner": "Not found",
                            "Carrier": "Not found",
                            "Country": "United States",
                            "Location": "Not found",
                            "National": "(833) 371-2570",
                            "Line Type": "TOLL FREE",
                            "Local Time": "02:43:29",
                            "Views count": "34",
                            "International": "+1 833-371-2570",
                        },
                        "Phone Number": "+18333712570",
                    },
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
