# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

from pyhashlookup import Hashlookup, PyHashlookupError

from api_app.analyzers_manager import classes
from api_app.analyzers_manager.exceptions import AnalyzerRunException


class HashLookupServer(classes.ObservableAnalyzer):
    hashlookup_server: str

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
