# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import logging

from api_app.analyzers_manager.classes import ObservableAnalyzer
from api_app.analyzers_manager.exceptions import AnalyzerRunException
from tests.mock_utils import if_mock_connections, patch

logger = logging.getLogger(__name__)


class DarkSearchQuery(ObservableAnalyzer):

    pages: int
    proxies: dict

    def run(self):
        from darksearch import Client, DarkSearchException

        try:
            c = Client(proxies=self.proxies)
            responses = c.search(self.observable_name, pages=self.pages)
        except DarkSearchException as exc:
            logger.error(exc)
            raise AnalyzerRunException(f"{exc.__class__.__name__}: {str(exc)}")

        result = {
            "total": responses[0]["total"],
            "total_pages": responses[0]["last_page"],
            "requested_pages": self.pages,
            "data": [],
        }
        for resp in responses:
            result["data"].extend(resp["data"])

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "darksearch.Client.search",
                    return_value=[{"total": 1, "last_page": 0, "data": ["test"]}],
                )
            )
        ]
        return super()._monkeypatch(patches=patches)
