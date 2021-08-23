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

        query = "{} site:bazaar.abuse.ch".format(self.observable_name)
        for url in googlesearch.search(query, stop=20):
            mb_hash = url.split("/")[-2]
            res = super(MB_GOOGLE, self).query_mb_api(observable_name=mb_hash)
            results[mb_hash] = res

        return results
