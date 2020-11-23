import googlesearch

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from api_app.script_analyzers.observable_analyzers import mb_get


class MB_GOOGLE(classes.ObservableAnalyzer):
    def run(self):
        if self.observable_classification not in ["ip", "domain", "url"]:
            raise AnalyzerRunException(
                f"not supported observable type {self.observable_classification}."
                f" Supported: ip, domain, url"
            )

        query = "{} site:bazaar.abuse.ch".format(self.observable_name)
        ret = []
        for url in googlesearch.search(query, stop=20):
            mb_hash = url.split("/")[-2]
            _mb_get = mb_get.MB_GET(
                "MalwareBazaar_Google_Observable", self.job_id, mb_hash, "hash", {}
            )
            res = _mb_get.start()
            ret.append(res)
            del _mb_get

        return ret
