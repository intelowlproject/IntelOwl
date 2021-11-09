# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from pyhashlookup import Hashlookup

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

        # lookup
        hash_length = len(self.observable_name)
        if hash_length == 32:
            result = hashlookup_instance.md5_lookup(self.observable_name)
        elif hash_length == 40:
            result = hashlookup_instance.sha1_lookup(self.observable_name)
        else:
            raise AnalyzerRunException(
                "hashes that are not md5 or sha1 are not supported by the service"
            )

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
