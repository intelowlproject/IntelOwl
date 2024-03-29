# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

import querycontacts

from api_app.analyzers_manager import classes
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class Abusix(classes.ObservableAnalyzer):
    def run(self):
        result = {}
        ip_addr = self.observable_name
        cf = querycontacts.ContactFinder()
        abuse_contacts = cf.find(ip_addr)
        if not abuse_contacts:
            abuse_contacts = []
        result["abuse_contacts"] = abuse_contacts
        return result

    def update(self) -> bool:
        pass

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "querycontacts.ContactFinder.find",
                    return_value=["network-abuse@google.com"],
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
