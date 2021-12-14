# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from pyhashlookup import Hashlookup, PyHashlookupError

from api_app.analyzers_manager import classes
from api_app.exceptions import AnalyzerRunException
from tests.mock_utils import MockResponseNoOp, if_mock_connections, patch


class HashLookupServer(classes.ObservableAnalyzer):
    def set_params(self, params):
        self.hashlookup_server = params.get("hashlookup_server", "")

    def run(self):
        if self.hashlookup_server:
            hashlookup_instance = Hashlookup(root_url=self.hashlookup_server)
        else:
            # the library maintains the default URL
            hashlookup_instance = Hashlookup()

        try:
            result = hashlookup_instance.lookup(self.observable_name)
        except PyHashlookupError as e:
            raise AnalyzerRunException(e)

        return result

    @classmethod
    def _monkeypatch(cls):
        patches = [
            if_mock_connections(
                patch(
                    "pyhashlookup.Hashlookup", return_value=MockResponseNoOp({}, 200)
                ),
            )
        ]
        return super()._monkeypatch(patches=patches)
