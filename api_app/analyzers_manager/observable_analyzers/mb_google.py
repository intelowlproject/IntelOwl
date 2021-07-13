# This file is a part of IntelOwl https://github.com/intelowlproject/IntelOwl
# See the file 'LICENSE' for copying permission.

import googlesearch

from .mb_get import MB_GET


class MB_GOOGLE(MB_GET):
    """
    This is a modified version of MB_GET.
    """

    def run(self):
        results = {}

        # save for later
        observable_name = self.observable_name

        query = "{} site:bazaar.abuse.ch".format(observable_name)
        for url in googlesearch.search(query, stop=20):
            mb_hash = url.split("/")[-2]
            # overwrite self.observable_name so super class works correctly
            self.observable_name = mb_hash
            res = super(MB_GOOGLE, self).run()
            results[mb_hash] = res

        # revert back
        self.observable_name = observable_name

        return results
