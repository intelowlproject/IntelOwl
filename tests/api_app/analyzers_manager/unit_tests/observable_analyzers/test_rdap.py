# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from unittest.mock import patch

from api_app.analyzers_manager.observable_analyzers.rdap import Rdap
from tests.api_app.analyzers_manager.unit_tests.observable_analyzers.base_test_class import (
    BaseAnalyzerTest,
)
from tests.mock_utils import MockUpResponse


class RdapTestCase(BaseAnalyzerTest):
    analyzer_class = Rdap

    @staticmethod
    def get_mocked_response():
        return patch(
            "requests.get",
            return_value=MockUpResponse(
                {
                    "objectClassName": "ip network",
                    "handle": "NET-8-8-8-0-1",
                    "startAddress": "8.8.8.0",
                    "endAddress": "8.8.8.255",
                    "ipVersion": "v4",
                    "name": "LVLT-GOGL-8-8-8",
                    "type": "DIRECT ALLOCATION",
                    "remarks": [
                        {
                            "title": "Registration Comments",
                            "description": ["This network is used by Google"],
                        }
                    ],
                    "links": [
                        {
                            "href": "https://rdap.arin.net/registry/ip/8.8.8.0",
                            "rel": "self",
                        }
                    ],
                    "entities": [
                        {
                            "objectClassName": "entity",
                            "handle": "GOGL",
                            "roles": ["registrant"],
                        }
                    ],
                    "found": True,
                },
                200,
            ),
        )
